import base64
import json
import logging

from oic.extension.client import Client as ClientExtension
from oic.oic import Client, RegistrationResponse, AuthorizationResponse, \
    AccessTokenResponse, TokenErrorResponse, AuthorizationErrorResponse
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

logger = logging.getLogger(__name__)


class _ClientAuthentication:
    def __init__(self, client_id, client_secret):
        self._client_id = client_id
        self._client_secret = client_secret

    def __call__(self, method, request):
        """
        Args:
            method (str): Client Authentication Method. Only 'client_secret_basic' and 'client_secret_post' is
                supported.
            request (MutableMapping[str, str]): Token request parameters. This may be modified, i.e. if
                'client_secret_post' is used the client credentials will be added.

        Returns:
            (Mapping[str, str]): HTTP headers to be included in the token request, or `None` if no extra HTTPS headers
            are required for the token request.
        """
        if method == 'client_secret_post':
            request['client_id'] = self._client_id
            request['client_secret'] = self._client_secret
            return None  # authentication is in the request body, so no Authorization header is returned

        # default to 'client_secret_basic'
        credentials = '{}:{}'.format(self._client_id, self._client_secret)
        basic_auth = 'Basic {}'.format(base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8'))
        return {'Authorization': basic_auth}


class PyoidcFacade:
    """
    Wrapper around pyoidc library, coupled with config for a simplified API for flask-pyoidc.
    """

    def __init__(self, provider_configuration, redirect_uri):
        """
        Args:
            provider_configuration (flask_pyoidc.provider_configuration.ProviderConfiguration)
        """
        self._provider_configuration = provider_configuration
        self._client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        # Token Introspection is implemented in extension sub-package of the
        # client in pyoidc
        self._client_extension = ClientExtension(client_authn_method=CLIENT_AUTHN_METHOD)

        provider_metadata = provider_configuration.ensure_provider_metadata()
        self._client.handle_provider_config(ProviderConfigurationResponse(**provider_metadata.to_dict()),
                                            provider_metadata['issuer'])

        if self._provider_configuration.registered_client_metadata:
            client_metadata = self._provider_configuration.registered_client_metadata.to_dict()
            registration_response = RegistrationResponse(**client_metadata)
            self._client.store_registration_info(registration_response)

        self._redirect_uri = redirect_uri

    def is_registered(self):
        return bool(self._provider_configuration.registered_client_metadata)

    def register(self, extra_registration_params=None):
        client_metadata = self._provider_configuration.register_client([self._redirect_uri], extra_registration_params)
        logger.debug('client registration response: %s', client_metadata)
        self._client.store_registration_info(RegistrationResponse(**client_metadata.to_dict()))

    def authentication_request(self, state, nonce, extra_auth_params):
        """

        Args:
            state (str): authentication request parameter 'state'
            nonce (str): authentication request parameter 'nonce'
            extra_auth_params (Mapping[str, str]): extra authentication request parameters
        Returns:
            AuthorizationRequest: the authentication request
        """
        args = {
            'client_id': self._client.client_id,
            'response_type': 'code',
            'scope': ['openid'],
            'redirect_uri': self._redirect_uri,
            'state': state,
            'nonce': nonce,
        }

        args.update(self._provider_configuration.auth_request_params)
        args.update(extra_auth_params)
        auth_request = self._client.construct_AuthorizationRequest(request_args=args)
        logger.debug('sending authentication request: %s', auth_request.to_json())

        return auth_request

    def login_url(self, auth_request):
        """
        Args:
            auth_request (AuthorizationRequest): authenticatio request
        Returns:
            str: Authentication request as a URL to redirect the user to the provider.
        """
        return auth_request.request(self._client.authorization_endpoint)

    def parse_authentication_response(self, response_params):
        """
        Args:
            response_params (Mapping[str, str]): authentication response parameters
        Returns:
            Union[AuthorizationResponse, AuthorizationErrorResponse]: The parsed authorization response
        """
        auth_resp = self._parse_response(response_params, AuthorizationResponse, AuthorizationErrorResponse)
        if 'id_token' in response_params:
            auth_resp['id_token_jwt'] = response_params['id_token']
        return auth_resp

    def exchange_authorization_code(self, authorization_code):
        """
        Requests tokens from an authorization code.

        Args:
            authorization_code (str): authorization code issued to client after user authorization

        Returns:
            Union[AccessTokenResponse, TokenErrorResponse, None]: The parsed token response, or None if no token
            request was performed.
        """
        request = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self._redirect_uri
        }

        return self._token_request(request)

    def verify_id_token(self, id_token, auth_request):
        """
        Verifies the ID Token.

        Args:
            id_token (Mapping[str, str]): ID token claims
            auth_request (Mapping[str, str]): original authentication request parameters to validate against
                (nonce, acr_values, max_age, etc.)

        Raises:
            PyoidcError: If the ID token is invalid.

        """
        self._client.verify_id_token(id_token, auth_request)

    def refresh_token(self, refresh_token):
        """
        Requests new tokens using a refresh token.

        Args:
            refresh_token (str): refresh token issued to client after user authorization

        Returns:
            Union[AccessTokenResponse, TokenErrorResponse, None]: The parsed token response, or None if no token
            request was performed.
        """
        request = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'redirect_uri': self._redirect_uri
        }

        return self._token_request(request)

    def _token_request(self, request):
        """
        Makes a token request.  If the 'token_endpoint' is not configured in the provider metadata, no request will
        be made.

        Args:
            request (Mapping[str, str]): token request parameters

        Returns:
            Union[AccessTokenResponse, TokenErrorResponse, None]: The parsed token response, or None if no token
            request was performed.
        """

        if not self._client.token_endpoint:
            return None

        logger.debug('making token request: %s', request)
        client_auth_method = self._client.registration_response.get('token_endpoint_auth_method', 'client_secret_basic')
        auth_header = _ClientAuthentication(self._client.client_id, self._client.client_secret)(client_auth_method,
                                                                                                request)
        resp = self._provider_configuration.requests_session \
            .post(self._client.token_endpoint,
                  data=request,
                  headers=auth_header) \
            .json()
        logger.debug('received token response: %s', json.dumps(resp))

        token_resp = self._parse_response(resp, AccessTokenResponse, TokenErrorResponse)
        if 'id_token' in resp:
            token_resp['id_token_jwt'] = resp['id_token']

        return token_resp

    def userinfo_request(self, access_token):
        """
        Args:
            access_token (str): Bearer access token to use when fetching userinfo

        Returns:
            oic.oic.message.OpenIDSchema: UserInfo Response
        """
        http_method = self._provider_configuration.userinfo_endpoint_method
        if not access_token or http_method is None or not self._client.userinfo_endpoint:
            return None

        logger.debug('making userinfo request')
        userinfo_response = self._client.do_user_info_request(method=http_method, token=access_token)
        logger.debug('received userinfo response: %s', userinfo_response.to_json())

        return userinfo_response

    def _token_introspection_request(self, access_token: str):
        """Make token introspection request.

        Parameters
        ----------
        access_token: str
            Access token to be validated.

        Returns
        -------
        oic.extension.message.TokenIntrospectionResponse
            Response object contains result of the token introspection.
        """
        args = {
            'token': access_token,
            'client_id': self._client.client_id,
            'client_secret': self._client.client_secret
        }
        token_introspection_request = self._client_extension.construct_TokenIntrospectionRequest(
            request_args=args
        )
        logger.info('making token introspection request')
        return self._client_extension.do_token_introspection(
            request_args=token_introspection_request,
            endpoint=self._client.introspection_endpoint)

    def client_credentials_grant(self):
        """Public method to request access_token using client_credentials flow.
        This is useful for service to service communication where user-agent is
        not available which is required in authorization code flow. Your
        service can request access_token in order to access APIs of other
        services.

        On API call, token introspection will ensure that only valid token can
        be used to access your APIs.

        Examples
        --------
        ::

            auth = OIDCAuthentication({'default': provider_config},
                                      access_token_required=True)
            auth.init_app(app)
            auth.clients['default'].client_credentials_grant()
        """
        client_credentials_payload = {
            'grant_type': 'client_credentials'
        }
        return self._token_request(request=client_credentials_payload)

    @property
    def session_refresh_interval_seconds(self):
        return self._provider_configuration.session_refresh_interval_seconds

    @property
    def provider_end_session_endpoint(self):
        provider_metadata = self._provider_configuration.ensure_provider_metadata()
        return provider_metadata.get('end_session_endpoint')

    @property
    def post_logout_redirect_uris(self):
        return self._client.registration_response.get('post_logout_redirect_uris')

    def _parse_response(self, response_params, success_response_cls, error_response_cls):
        if 'error' in response_params:
            response = error_response_cls(**response_params)
        else:
            response = success_response_cls(**response_params)
            response.verify(keyjar=self._client.keyjar)
        return response
