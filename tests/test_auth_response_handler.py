import pytest
from oic.oic import AuthorizationResponse, AccessTokenResponse, IdToken, TokenErrorResponse, \
    OpenIDSchema, AuthorizationErrorResponse
from unittest.mock import create_autospec

from flask_pyoidc.auth_response_handler import AuthResponseHandler, AuthResponseUnexpectedStateError, \
    AuthResponseUnexpectedNonceError, AuthResponseErrorResponseError, AuthResponseMismatchingSubjectError
from flask_pyoidc.pyoidc_facade import PyoidcFacade


class TestAuthResponseHandler:
    AUTH_RESPONSE = AuthorizationResponse(**{'code': 'test_auth_code', 'state': 'test_state'})
    TOKEN_RESPONSE = AccessTokenResponse(**{
        'access_token': 'test_token',
        'expires_in': 3600,
        'id_token': IdToken(**{'sub': 'test_sub', 'nonce': 'test_nonce'}),
        'id_token_jwt': 'test_id_token_jwt'
    })
    USERINFO_RESPONSE = OpenIDSchema(**{'sub': 'test_sub'})
    ERROR_RESPONSE = {'error': 'test_error', 'error_description': 'something went wrong'}

    @pytest.fixture
    def client_mock(self):
        return create_autospec(PyoidcFacade, True, True)

    def test_should_detect_state_mismatch(self, client_mock):
        with pytest.raises(AuthResponseUnexpectedStateError):
            AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE, 'other_state')

    def test_should_detect_nonce_mismatch(self, client_mock):
        client_mock.token_request.return_value = self.TOKEN_RESPONSE
        with pytest.raises(AuthResponseUnexpectedNonceError):
            AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE,
                                                                   self.AUTH_RESPONSE['state'],
                                                                   'other_nonce')

    def test_should_handle_auth_error_response(self, client_mock):
        with pytest.raises(AuthResponseErrorResponseError) as exc:
            AuthResponseHandler(client_mock).process_auth_response(AuthorizationErrorResponse(**self.ERROR_RESPONSE),
                                                                   self.AUTH_RESPONSE['state'])
        assert exc.value.error_response == self.ERROR_RESPONSE

    def test_should_handle_token_error_response(self, client_mock):
        client_mock.token_request.return_value = TokenErrorResponse(**self.ERROR_RESPONSE)
        with pytest.raises(AuthResponseErrorResponseError) as exc:
            AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                   self.AUTH_RESPONSE['state'])
        assert exc.value.error_response == self.ERROR_RESPONSE

    def test_should_detect_mismatching_subject(self, client_mock):
        client_mock.token_request.return_value = AccessTokenResponse(**self.TOKEN_RESPONSE)
        client_mock.userinfo_request.return_value = OpenIDSchema(**{'sub': 'other_sub'})
        with pytest.raises(AuthResponseMismatchingSubjectError):
            AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                   self.AUTH_RESPONSE['state'],
                                                                   self.TOKEN_RESPONSE['id_token']['nonce'])

    def test_should_handle_auth_response_with_authorization_code(self, client_mock):
        client_mock.token_request.return_value = self.TOKEN_RESPONSE
        client_mock.userinfo_request.return_value = self.USERINFO_RESPONSE
        result = AuthResponseHandler(client_mock).process_auth_response(self.AUTH_RESPONSE,
                                                                        self.AUTH_RESPONSE['state'],
                                                                        self.TOKEN_RESPONSE['id_token']['nonce'])
        assert result.access_token == 'test_token'
        assert result.expires_in == self.TOKEN_RESPONSE['expires_in']
        assert result.id_token_claims == self.TOKEN_RESPONSE['id_token'].to_dict()
        assert result.id_token_jwt == self.TOKEN_RESPONSE['id_token_jwt']
        assert result.userinfo_claims == self.USERINFO_RESPONSE.to_dict()

    def test_should_handle_auth_response_without_authorization_code(self, client_mock):
        auth_response = AuthorizationResponse(**self.TOKEN_RESPONSE)
        auth_response['state'] = 'test_state'
        client_mock.userinfo_request.return_value = self.USERINFO_RESPONSE
        result = AuthResponseHandler(client_mock).process_auth_response(auth_response, 'test_state')
        assert not client_mock.token_request.called
        assert result.access_token == 'test_token'
        assert result.expires_in == self.TOKEN_RESPONSE['expires_in']
        assert result.id_token_jwt == self.TOKEN_RESPONSE['id_token_jwt']
        assert result.id_token_claims == self.TOKEN_RESPONSE['id_token'].to_dict()
        assert result.userinfo_claims == self.USERINFO_RESPONSE.to_dict()

    def test_should_handle_token_response_without_id_token(self, client_mock):
        token_response = {'access_token': 'test_token'}
        client_mock.token_request.return_value = AccessTokenResponse(**token_response)
        result = AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                        self.AUTH_RESPONSE['state'],
                                                                        self.TOKEN_RESPONSE['id_token']['nonce'])
        assert result.access_token == 'test_token'
        assert result.id_token_claims is None

    def test_should_handle_no_token_response(self, client_mock):
        client_mock.token_request.return_value = None
        client_mock.userinfo_request.return_value = None
        hybrid_auth_response = self.AUTH_RESPONSE.copy()
        hybrid_auth_response.update(self.TOKEN_RESPONSE)
        result = AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**hybrid_auth_response),
                                                                        self.AUTH_RESPONSE['state'],
                                                                        self.TOKEN_RESPONSE['id_token']['nonce'])
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
