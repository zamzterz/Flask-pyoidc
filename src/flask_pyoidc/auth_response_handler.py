import collections
import logging

from oic.exception import PyoidcError

logger = logging.getLogger(__name__)

AuthenticationResult = collections.namedtuple('AuthenticationResult',
                                              [
                                                  'access_token',
                                                  'expires_in',
                                                  'id_token_claims',
                                                  'id_token_jwt',
                                                  'userinfo_claims',
                                                  'refresh_token'
                                              ])


class AuthResponseProcessError(ValueError):
    pass


class AuthResponseUnexpectedStateError(AuthResponseProcessError):
    pass


class InvalidIdTokenError(AuthResponseProcessError):
    pass


class AuthResponseMismatchingSubjectError(AuthResponseProcessError):
    pass


class AuthResponseErrorResponseError(AuthResponseProcessError):
    def __init__(self, error_response):
        """
        Args:
            error_response (Mapping[str, str]): OAuth error response containing 'error' and 'error_description'
        """
        self.error_response = error_response


class AuthResponseHandler:
    def __init__(self, client):
        """
        Args:
            client (flask_pyoidc.pyoidc_facade.PyoidcFacade): Client proxy to make requests to the provider
        """
        self._client = client

    def process_auth_response(self, auth_response, auth_request):
        """
        Args:
            auth_response (Union[AuthorizationResponse, AuthorizationErrorResponse]): parsed OIDC auth response
            auth_request (Mapping[str, str]): original OIDC auth request
        Returns:
            AuthenticationResult: All relevant data associated with the authenticated user
        """
        if 'error' in auth_response:
            raise AuthResponseErrorResponseError(auth_response.to_dict())

        if auth_response['state'] != auth_request['state']:
            raise AuthResponseUnexpectedStateError()

        # implicit/hybrid flow may return tokens in the auth response
        access_token = auth_response.get('access_token', None)
        expires_in = auth_response.get('expires_in', None)
        id_token_claims = auth_response['id_token'].to_dict() if 'id_token' in auth_response else None
        id_token_jwt = auth_response.get('id_token_jwt', None)
        refresh_token = None  # but never refresh token

        if 'code' in auth_response:
            token_resp = self._client.exchange_authorization_code(auth_response['code'])
            if token_resp:
                if 'error' in token_resp:
                    raise AuthResponseErrorResponseError(token_resp.to_dict())

                access_token = token_resp['access_token']
                expires_in = token_resp.get('expires_in', None)
                refresh_token = token_resp.get('refresh_token', None)

                if 'id_token' in token_resp:
                    id_token = token_resp['id_token']
                    logger.debug('received id token: %s', id_token.to_json())

                    try:
                        self._client.verify_id_token(id_token, auth_request)
                    except PyoidcError as e:
                        raise InvalidIdTokenError(str(e))

                    id_token_claims = id_token.to_dict()
                    id_token_jwt = token_resp.get('id_token_jwt')

        # do userinfo request
        userinfo = self._client.userinfo_request(access_token)
        userinfo_claims = None
        if userinfo:
            userinfo_claims = userinfo.to_dict()

        if id_token_claims and userinfo_claims and userinfo_claims['sub'] != id_token_claims['sub']:
            raise AuthResponseMismatchingSubjectError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

        return AuthenticationResult(access_token,
                                    expires_in,
                                    id_token_claims,
                                    id_token_jwt,
                                    userinfo_claims,
                                    refresh_token)

    @classmethod
    def expect_fragment_encoded_response(cls, auth_request):
        if 'response_mode' in auth_request:
            return auth_request['response_mode'] == 'fragment'

        response_type = set(auth_request['response_type'].split(' '))
        is_implicit_flow = response_type == {'id_token'} or \
                           response_type == {'id_token', 'token'}
        is_hybrid_flow = response_type == {'code', 'id_token'} or \
                         response_type == {'code', 'token'} or \
                         response_type == {'code', 'id_token', 'token'}

        return is_implicit_flow or is_hybrid_flow
