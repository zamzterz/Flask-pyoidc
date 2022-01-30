import collections.abc
import logging

from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
import requests

logger = logging.getLogger(__name__)


class OIDCData(collections.abc.MutableMapping):
    """
    Basic OIDC data representation providing validation of required fields.
    """

    def __init__(self, *args, **kwargs):
        """
        Args:
            args (List[Tuple[String, String]]): key-value pairs to store
            kwargs (Dict[string, string]): key-value pairs to store
        """
        self.store = dict()
        self.update(dict(*args, **kwargs))

    def __getitem__(self, key):
        return self.store[key]

    def __setitem__(self, key, value):
        self.store[key] = value

    def __delitem__(self, key):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def __str__(self):
        data = self.store.copy()
        if 'client_secret' in data:
            data['client_secret'] = '<masked>'
        return str(data)

    def __repr__(self):
        return str(self.store)

    def __bool__(self):
        return True

    def copy(self, **kwargs):
        values = self.to_dict()
        values.update(kwargs)
        return self.__class__(**values)

    def to_dict(self):
        return self.store.copy()


class ProviderMetadata(OIDCData):

    def __init__(self, issuer=None, authorization_endpoint=None, token_endpoint=None,
                 userinfo_endpoint=None, jwks_uri=None, introspection_endpoint=None,
                 registration_endpoint=None, **kwargs):
        """OpenID Providers have metadata describing their configuration.

        Parameters
        ----------
        issuer: str, Optional
            OP Issuer Identifier.
        authorization_endpoint: str, Optional
            URL of the OP's OAuth 2.0 Authorization Endpoint.
        token_endpoint: str, Optional
            URL of the OP's OAuth 2.0 Token Endpoint.
        userinfo_endpoint: str, Optional
            URL of the OP's UserInfo Endpoint.
        jwks_uri: str, Optional
            URL of the OP's JSON Web Key Set [JWK] document.
        introspection_endpoint: str, Optional
            URL of the OP's token introspection endpoint.
        registration_endpoint: str, Optional
            URL of the OP's Dynamic Client Registration Endpoint.
        **kwargs : dict, Optional
            Extra arguments to [OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
        """
        super().__init__(issuer=issuer, authorization_endpoint=authorization_endpoint,
                         token_endpoint=token_endpoint, userinfo_endpoint=userinfo_endpoint,
                         jwks_uri=jwks_uri, introspection_endpoint=introspection_endpoint,
                         registration_endpoint=registration_endpoint, **kwargs)


class ClientRegistrationInfo(OIDCData):
    pass


class ClientMetadata(OIDCData):
    def __init__(self, client_id=None, client_secret=None, **kwargs):
        """
        Args:
            client_id (str): client identifier representing the client
            client_secret (str): client secret to authenticate the client with
                the OP
            kwargs (dict): key-value pairs
        """
        super(ClientMetadata, self).__init__(client_id=client_id, client_secret=client_secret, **kwargs)


class ProviderConfiguration:
    """
    Metadata for communicating with an OpenID Connect Provider (OP).

    Attributes:
        auth_request_params (dict): Extra parameters, as key-value pairs, to include in the query parameters
            of the authentication request
        registered_client_metadata (ClientMetadata): The client metadata registered with the provider.
        requests_session (requests.Session): Requests object to use when communicating with the provider.
        session_refresh_interval_seconds (int): Number of seconds between updates of user data (tokens, user data, etc.)
            fetched from the provider. If `None` is specified, no silent updates should be made user data will be made.
        userinfo_endpoint_method (str): HTTP method ("GET" or "POST") to use when making the UserInfo Request. If
            `None` is specifed, no UserInfo Request will be made.
    """

    DEFAULT_REQUEST_TIMEOUT = 5

    def __init__(self,
                 issuer=None,
                 provider_metadata=None,
                 userinfo_http_method='GET',
                 client_registration_info=None,
                 client_metadata=None,
                 auth_request_params=None,
                 session_refresh_interval_seconds=None,
                 requests_session=None):
        """
        Args:
            issuer (str): OP Issuer Identifier. If this is specified discovery will be used to fetch the provider
                metadata, otherwise `provider_metadata` must be specified.
            provider_metadata (ProviderMetadata): OP metadata,
            userinfo_http_method (Optional[str]): HTTP method (GET or POST) to use when sending the UserInfo Request.
                If `none` is specified, no userinfo request will be sent.
            client_registration_info (ClientRegistrationInfo): Client metadata to register your app
                dynamically with the provider. Either this or `registered_client_metadata` must be specified.
            client_metadata (ClientMetadata): Client metadata if your app is statically
                registered with the provider. Either this or `client_registration_info` must be specified.
            auth_request_params (dict): Extra parameters that should be included in the authentication request.
            session_refresh_interval_seconds (int): Length of interval (in seconds) between attempted user data
                refreshes.
            requests_session (requests.Session): custom requests object to allow for example retry handling, etc.
        """

        if not issuer and not provider_metadata:
            raise ValueError("Specify either 'issuer' or 'provider_metadata'.")

        if not client_registration_info and not client_metadata:
            raise ValueError("Specify either 'client_registration_info' or 'client_metadata'.")

        self._issuer = issuer
        self._provider_metadata = provider_metadata

        self._client_registration_info = client_registration_info
        self._client_metadata = client_metadata

        self.userinfo_endpoint_method = userinfo_http_method
        self.auth_request_params = auth_request_params or {}
        self.session_refresh_interval_seconds = session_refresh_interval_seconds

        self.requests_session = requests_session or requests.Session()

        self._client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

    def ensure_provider_metadata(self):
        if not self._provider_metadata:
            resp = self.requests_session \
                .get(self._issuer + '/.well-known/openid-configuration',
                     timeout=self.DEFAULT_REQUEST_TIMEOUT)
            logger.debug('Received discovery response: ' + resp.text)

            self._provider_metadata = ProviderMetadata(**resp.json())

        return self._provider_metadata

    @property
    def registered_client_metadata(self):
        return self._client_metadata

    def register_client(self, redirect_uris, extra_parameters=None):
        if not self._client_metadata:
            if 'registration_endpoint' not in self._provider_metadata:
                raise ValueError("Can't use dynamic client registration, provider metadata is missing "
                                 "'registration_endpoint'.")

            registration_request = self._client_registration_info.to_dict()
            registration_request['redirect_uris'] = redirect_uris
            if extra_parameters:
                registration_request.update(extra_parameters)

            registration_response = self._client.register(
                url=self._provider_metadata['registration_endpoint'],
                registration_token=registration_request.get('initial_access_token'),
                **registration_request)
            logger.debug(registration_response.to_dict())
            self._client_metadata = ClientMetadata(**registration_response.to_dict())
            logger.debug('Received registration response: client_id=' + self._client_metadata['client_id'])

        return self._client_metadata
