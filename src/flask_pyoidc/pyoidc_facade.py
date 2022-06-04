import base64
import logging

from oic.extension.client import Client as ClientExtension
from oic.extension.message import TokenIntrospectionResponse
from oic.oauth2 import Client as Oauth2Client
from oic.oauth2.message import AccessTokenResponse
from oic.oic import Client
from oic.oic import Token
from oic.oic.message import AuthorizationResponse, ProviderConfigurationResponse, RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from .message_factory import CCMessageFactory

logger = logging.getLogger(__name__)


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
        self._client = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                              settings=provider_configuration.requests_session)
        # Token Introspection is implemented under extension sub-package of
        # the client in pyoidc.
        self._client_extension = ClientExtension(client_authn_method=CLIENT_AUTHN_METHOD,
                                                 settings=provider_configuration.requests_session)
        # Client Credentials Flow is implemented under oauth2 sub-package of
        # the client in pyoidc.
        self._oauth2_client = Oauth2Client(client_authn_method=CLIENT_AUTHN_METHOD,
                                           message_factory=CCMessageFactory,
                                           settings=self._provider_configuration.requests_session)

        provider_metadata = provider_configuration.ensure_provider_metadata(self._client)
        self._client.handle_provider_config(ProviderConfigurationResponse(**provider_metadata.to_dict()),
                                            provider_metadata['issuer'])

        if self._provider_configuration.registered_client_metadata:
            client_metadata = self._provider_configuration.registered_client_metadata.to_dict()
            client_metadata.update(redirect_uris=list(redirect_uri))
            self._store_registration_info(client_metadata)

        self._redirect_uri = redirect_uri

    def _store_registration_info(self, client_metadata):
        registration_response = RegistrationResponse(**client_metadata)
        self._client.store_registration_info(registration_response)
        self._client_extension.store_registration_info(registration_response)
        # Set client_id and client_secret for _oauth2_client. This is used
        # by Client Credentials Flow.
        self._oauth2_client.client_id = registration_response['client_id']
        self._oauth2_client.client_secret = registration_response['client_secret']

    def is_registered(self):
        return bool(self._provider_configuration.registered_client_metadata)

    def register(self):
        client_metadata = self._provider_configuration.register_client(self._client)
        logger.debug(f'client registration response: {client_metadata}')
        self._store_registration_info(client_metadata)

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
            auth_request (AuthorizationRequest): authentication request
        Returns:
            str: Authentication request as a URL to redirect the user to the provider.
        """
        return auth_request.request(self._client.authorization_endpoint)

    def parse_authentication_response(self, response_params):
        """
        Parameters
        ----------
        response_params: Mapping[str, str]
            authentication response parameters.

        Returns
        -------
        Union[AuthorizationResponse, AuthorizationErrorResponse]
            The parsed authorization response.
        """
        auth_resp = self._client.parse_response(AuthorizationResponse, info=response_params, sformat='dict')
        if 'id_token' in response_params:
            auth_resp['id_token_jwt'] = response_params['id_token']
        return auth_resp

    def exchange_authorization_code(self, authorization_code: str, state: str):
        """Requests tokens from an authorization code.

        Parameters
        ----------
        authorization_code: str
            authorization code issued to client after user authorization
        state: str
            state is used to keep track of responses to outstanding requests.

        Returns
        -------
        Union[AccessTokenResponse, TokenErrorResponse, None]
            The parsed token response, or None if no token request was performed.
        """
        if not self._client.token_endpoint:
            return None

        request_args = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self._redirect_uri
        }
        logger.debug('making token request: %s', request_args)
        client_auth_method = self._client.registration_response.get('token_endpoint_auth_method',
                                                                    'client_secret_basic')
        token_response = self._client.do_access_token_request(state=state,
                                                              request_args=request_args,
                                                              authn_method=client_auth_method,
                                                              endpoint=self._client.token_endpoint
                                                              )
        logger.debug(f'received token response: {token_response}')

        return token_response

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

    def refresh_token(self, refresh_token: str):
        """Requests new tokens using a refresh token.

        Parameters
        ----------
        refresh_token: str
            refresh token issued to client after user authorization.

        Returns
        -------
        Union[AccessTokenResponse, TokenErrorResponse, None]
            The parsed token response, or None if no token request was performed.
        """
        request_args = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'redirect_uri': self._redirect_uri
        }
        client_auth_method = self._client.registration_response.get('token_endpoint_auth_method',
                                                                    'client_secret_basic')
        return self._client.do_access_token_refresh(request_args=request_args,
                                                    authn_method=client_auth_method,
                                                    token=Token(resp={'refresh_token': refresh_token}),
                                                    endpoint=self._client.token_endpoint
                                                    )

    def userinfo_request(self, access_token: str):
        """Retrieves ID token.

        Parameters
        ----------
        access_token: str
            Bearer access token to use when fetching userinfo.

        Returns
        -------
        Union[OpenIDSchema, UserInfoErrorResponse, ErrorResponse, None]
        """
        http_method = self._provider_configuration.userinfo_endpoint_method
        if not access_token or http_method is None or not self._client.userinfo_endpoint:
            return None

        logger.debug('making userinfo request')
        userinfo_response = self._client.do_user_info_request(method=http_method, token=access_token)
        logger.debug('received userinfo response: %s', userinfo_response)

        return userinfo_response

    def _token_introspection_request(self, access_token: str) -> TokenIntrospectionResponse:
        """Make token introspection request.

        Parameters
        ----------
        access_token: str
            Access token to be validated.

        Returns
        -------
        TokenIntrospectionResponse
            Response object contains result of the token introspection.
        """
        request_args = {
            'token': access_token,
            'token_type_hint': 'access_token'
        }
        client_auth_method = self._client.registration_response.get('introspection_endpoint_auth_method',
                                                                    'client_secret_basic')
        logger.info('making token introspection request')
        token_introspection_response = self._client_extension.do_token_introspection(
            request_args=request_args, authn_method=client_auth_method, endpoint=self._client.introspection_endpoint)

        return token_introspection_response

    def client_credentials_grant(self, scope: list = None, **kwargs) -> AccessTokenResponse:
        """Public method to request access_token using client_credentials flow.
        This is useful for service to service communication where user-agent is
        not available which is required in authorization code flow. Your
        service can request access_token in order to access APIs of other
        services.

        On API call, token introspection will ensure that only valid token can
        be used to access your APIs.

        Parameters
        ----------
        scope: list, optional
            List of scopes to be requested.
        **kwargs : dict, optional
            Extra arguments to client credentials flow.

        Returns
        -------
        AccessTokenResponse

        Examples
        --------
        ::

            auth = OIDCAuthentication({'default': provider_config},
                                      access_token_required=True)
            auth.init_app(app)
            auth.clients['default'].client_credentials_grant()

        Optionally, you can specify scopes for the access token.

        ::

            auth.clients['default'].client_credentials_grant(
                scope=['read', 'write'])

        You can also specify extra keyword arguments to client credentials flow.

        ::

            auth.clients['default'].client_credentials_grant(
                scope=['read', 'write'], audience=['client_id1', 'client_id2'])
        """
        request_args = {
            'grant_type': 'client_credentials',
            **kwargs
        }
        if scope:
            request_args['scope'] = ' '.join(scope)
        client_auth_method = self._client.registration_response.get('token_endpoint_auth_method',
                                                                    'client_secret_basic')
        access_token = self._oauth2_client.do_access_token_request(request_args=request_args,
                                                                   authn_method=client_auth_method,
                                                                   endpoint=self._client.token_endpoint)
        return access_token

    @property
    def session_refresh_interval_seconds(self):
        return self._provider_configuration.session_refresh_interval_seconds

    @property
    def provider_end_session_endpoint(self):
        provider_metadata = self._provider_configuration.ensure_provider_metadata(self._client)
        return provider_metadata.get('end_session_endpoint')

    @property
    def post_logout_redirect_uris(self):
        return self._client.registration_response.get('post_logout_redirect_uris')
