from time import time
from unittest.mock import create_autospec, MagicMock

import pytest
from flask_pyoidc.auth_response_handler import AuthResponseHandler, AuthResponseUnexpectedStateError, \
    InvalidIdTokenError, AuthResponseErrorResponseError, AuthResponseMismatchingSubjectError
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata
from flask_pyoidc.pyoidc_facade import PyoidcFacade
from oic.oic import AuthorizationResponse, AccessTokenResponse, IdToken, TokenErrorResponse, \
    OpenIDSchema, AuthorizationErrorResponse, AuthorizationRequest


def _create_id_token(issuer, client_id, nonce):
    id_token = IdToken(**{'iss': issuer, 'sub': 'test_sub', 'aud': client_id, 'nonce': nonce, 'exp': time() + 60})
    id_token.jws_header = {'alg': 'RS256'}
    return id_token


class TestAuthResponseHandler:
    ISSUER = 'https://issuer.example.com'
    CLIENT_ID = 'client1'
    AUTH_REQUEST = AuthorizationRequest(**{'state': 'test_state', 'nonce': 'test_nonce'})
    AUTH_RESPONSE = AuthorizationResponse(**{'code': 'test_auth_code', 'state': AUTH_REQUEST['state']})
    TOKEN_RESPONSE = AccessTokenResponse(**{
        'access_token': 'test_token',
        'expires_in': 3600,
        'id_token': _create_id_token(ISSUER, CLIENT_ID, AUTH_REQUEST['nonce']),
        'id_token_jwt': 'test_id_token_jwt',
        'refresh_token': 'test_refresh_token'
    })
    USERINFO_RESPONSE = OpenIDSchema(**{'sub': 'test_sub'})
    ERROR_RESPONSE = {'error': 'test_error', 'error_description': 'something went wrong'}

    @pytest.fixture
    def client_mock(self):
        return create_autospec(PyoidcFacade, True, True)

    def test_should_detect_state_mismatch(self, client_mock):
        auth_request = {'state': 'other_state', 'nonce': self.AUTH_REQUEST['nonce']}
        with pytest.raises(AuthResponseUnexpectedStateError):
            AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE, auth_request)

    def test_should_detect_nonce_mismatch(self, client_mock):
        client = PyoidcFacade(
            ProviderConfiguration(provider_metadata=ProviderMetadata(issuer=self.ISSUER),
                                  client_metadata=ClientMetadata(client_id=self.CLIENT_ID)),
            redirect_uri='https://client.example.com/redirect')
        client.exchange_authorization_code = MagicMock(return_value=self.TOKEN_RESPONSE)
        auth_request = {'state': self.AUTH_RESPONSE['state'], 'nonce': 'other_nonce'}
        with pytest.raises(InvalidIdTokenError):
            AuthResponseHandler(client).process_auth_response(self.AUTH_RESPONSE, auth_request)

    def test_should_handle_auth_error_response(self, client_mock):
        with pytest.raises(AuthResponseErrorResponseError) as exc:
            AuthResponseHandler(client_mock).process_auth_response(AuthorizationErrorResponse(**self.ERROR_RESPONSE),
                                                                   self.AUTH_REQUEST)
        assert exc.value.error_response == self.ERROR_RESPONSE

    def test_should_handle_token_error_response(self, client_mock):
        client_mock.exchange_authorization_code.return_value = TokenErrorResponse(**self.ERROR_RESPONSE)
        with pytest.raises(AuthResponseErrorResponseError) as exc:
            AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                   self.AUTH_REQUEST)
        assert exc.value.error_response == self.ERROR_RESPONSE

    def test_should_detect_mismatching_subject(self, client_mock):
        client_mock.exchange_authorization_code.return_value = AccessTokenResponse(**self.TOKEN_RESPONSE)
        client_mock.userinfo_request.return_value = OpenIDSchema(**{'sub': 'other_sub'})
        with pytest.raises(AuthResponseMismatchingSubjectError):
            AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                   self.AUTH_REQUEST)

    def test_should_handle_auth_response_with_authorization_code(self, client_mock):
        client_mock.exchange_authorization_code.return_value = self.TOKEN_RESPONSE
        client_mock.userinfo_request.return_value = self.USERINFO_RESPONSE
        result = AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE,
                                                                        self.AUTH_REQUEST)
        assert result.access_token == 'test_token'
        assert result.expires_in == self.TOKEN_RESPONSE['expires_in']
        assert result.id_token_claims == self.TOKEN_RESPONSE['id_token'].to_dict()
        assert result.id_token_jwt == self.TOKEN_RESPONSE['id_token_jwt']
        assert result.userinfo_claims == self.USERINFO_RESPONSE.to_dict()
        assert result.refresh_token == self.TOKEN_RESPONSE['refresh_token']

    def test_should_handle_auth_response_without_authorization_code(self, client_mock):
        auth_response = AuthorizationResponse(**self.TOKEN_RESPONSE)
        auth_response['state'] = 'test_state'
        client_mock.userinfo_request.return_value = self.USERINFO_RESPONSE
        result = AuthResponseHandler(client_mock).process_auth_response(auth_response, self.AUTH_REQUEST)
        assert not client_mock.exchange_authorization_code.called
        assert result.access_token == 'test_token'
        assert result.expires_in == self.TOKEN_RESPONSE['expires_in']
        assert result.id_token_jwt == self.TOKEN_RESPONSE['id_token_jwt']
        assert result.id_token_claims == self.TOKEN_RESPONSE['id_token'].to_dict()
        assert result.userinfo_claims == self.USERINFO_RESPONSE.to_dict()
        assert result.refresh_token == None

    def test_should_handle_token_response_without_id_token(self, client_mock):
        token_response = {'access_token': 'test_token'}
        client_mock.exchange_authorization_code.return_value = AccessTokenResponse(**token_response)
        result = AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                        self.AUTH_REQUEST)
        assert result.access_token == 'test_token'
        assert result.id_token_claims is None

    def test_should_handle_no_token_response(self, client_mock):
        client_mock.exchange_authorization_code.return_value = None
        client_mock.userinfo_request.return_value = None
        hybrid_auth_response = self.AUTH_RESPONSE.copy()
        hybrid_auth_response.update(self.TOKEN_RESPONSE)
        result = AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**hybrid_auth_response),
                                                                        self.AUTH_REQUEST)
        assert result.access_token == 'test_token'
        assert result.id_token_claims == self.TOKEN_RESPONSE['id_token'].to_dict()
        assert result.id_token_jwt == self.TOKEN_RESPONSE['id_token_jwt']

    @pytest.mark.parametrize('response_type, expected', [
        ('code', False),  # Authorization Code Flow
        ('id_token', True),  # Implicit Flow
        ('id_token token', True),  # Implicit Flow
        ('code id_token', True),  # Hybrid Flow
        ('code token', True),  # Hybrid Flow
        ('code id_token token', True)  # Hybrid Flow
    ])
    def test_expect_fragment_encoded_response_by_response_type(self, response_type, expected):
        assert AuthResponseHandler.expect_fragment_encoded_response({'response_type': response_type}) is expected

    @pytest.mark.parametrize('response_type, response_mode, expected', [
        ('code', 'fragment', True),
        ('id_token', 'query', False),
        ('code token', 'form_post', False),
    ])
    def test_expect_fragment_encoded_response_with_non_default_response_mode(self,
                                                                             response_type,
                                                                             response_mode,
                                                                             expected):
        auth_req = {'response_type': response_type, 'response_mode': response_mode}
        assert AuthResponseHandler.expect_fragment_encoded_response(auth_req) is expected
