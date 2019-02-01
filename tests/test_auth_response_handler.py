import pytest
from mock import create_autospec
from oic.oic import AuthorizationResponse, AccessTokenResponse, IdToken, TokenErrorResponse, \
    OpenIDSchema, AuthorizationErrorResponse

from flask_pyoidc.auth_response_handler import AuthResponseHandler, AuthResponseUnexpectedStateError, \
    AuthResponseUnexpectedNonceError, AuthResponseErrorResponseError, AuthResponseMismatchingSubjectError
from flask_pyoidc.pyoidc_facade import PyoidcFacade


class TestAuthResponseHandler:
    AUTH_RESPONSE = AuthorizationResponse(**{'code': 'test_auth_code', 'state': 'test_state'})
    TOKEN_RESPONSE = AccessTokenResponse(**{
        'access_token': 'test_token',
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
        assert result.id_token_claims == self.TOKEN_RESPONSE['id_token'].to_dict()
        assert result.id_token_jwt == self.TOKEN_RESPONSE['id_token_jwt']
        assert result.userinfo_claims == self.USERINFO_RESPONSE.to_dict()

    def test_should_handle_token_response_without_id_token(self, client_mock):
        token_response = {'access_token': 'test_token'}
        client_mock.token_request.return_value = AccessTokenResponse(**token_response)
        result = AuthResponseHandler(client_mock).process_auth_response(AuthorizationResponse(**self.AUTH_RESPONSE),
                                                                        self.AUTH_RESPONSE['state'],
                                                                        self.TOKEN_RESPONSE['id_token']['nonce'])
        assert result.access_token == 'test_token'
        assert result.id_token_claims is None
