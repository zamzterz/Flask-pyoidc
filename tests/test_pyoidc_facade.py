import time
from urllib.parse import parse_qsl

import pytest
import responses
from oic.oic import (AccessTokenResponse, AuthorizationErrorResponse,
                     AuthorizationResponse, Grant, OpenIDSchema,
                     TokenErrorResponse)

from flask_pyoidc.provider_configuration import (ClientMetadata,
                                                 ClientRegistrationInfo,
                                                 ProviderConfiguration,
                                                 ProviderMetadata)
from flask_pyoidc.pyoidc_facade import PyoidcFacade

from .util import signed_id_token

REDIRECT_URI = 'https://rp.example.com/redirect_uri'


class TestPyoidcFacade:
    PROVIDER_BASEURL = 'https://op.example.com'
    PROVIDER_METADATA = ProviderMetadata(issuer=PROVIDER_BASEURL,
                                         authorization_endpoint=PROVIDER_BASEURL + '/auth',
                                         jwks_uri=PROVIDER_BASEURL + '/jwks')
    CLIENT_METADATA = ClientMetadata('client1', 'secret1')

    @pytest.mark.parametrize('provider_config', [
        {'issuer': PROVIDER_BASEURL, 'client_registration_info': ClientRegistrationInfo()},
        {'provider_metadata': PROVIDER_METADATA, 'client_metadata': CLIENT_METADATA}
    ])
    @responses.activate
    def test_should_handle_provider_config_with_static_and_dynamic_provider(self, provider_config):
        provider_metadata = {
            'issuer': self.PROVIDER_BASEURL,
            'authorization_endpoint': self.PROVIDER_BASEURL + '/auth',
            'jwks_uri': self.PROVIDER_BASEURL + '/jwks'
        }
        responses.add(responses.GET,
                      self.PROVIDER_BASEURL + '/.well-known/openid-configuration',
                      json=provider_metadata)

        config = ProviderConfiguration(**provider_config)
        facade = PyoidcFacade(config, REDIRECT_URI)
        assert facade._client.issuer == self.PROVIDER_BASEURL

    def test_registered_client_metadata_is_forwarded_to_pyoidc(self):
        config = ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA, client_metadata=self.CLIENT_METADATA)
        facade = PyoidcFacade(config, REDIRECT_URI)

        expected = {
            'client_id': self.CLIENT_METADATA['client_id'],
            'client_secret': self.CLIENT_METADATA['client_secret'],
            'redirect_uris': [REDIRECT_URI],
            'token_endpoint_auth_method': 'client_secret_basic'
        }
        assert facade._client.registration_response.to_dict() == expected

    def test_no_registered_client_metadata_is_handled(self):
        config = ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                       client_registration_info=ClientRegistrationInfo())
        facade = PyoidcFacade(config, REDIRECT_URI)
        assert not facade._client.registration_response

    def test_is_registered(self):
        unregistered = ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                             client_registration_info=ClientRegistrationInfo())
        registered = ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                           client_metadata=self.CLIENT_METADATA)
        assert PyoidcFacade(unregistered, REDIRECT_URI).is_registered() is False
        assert PyoidcFacade(registered, REDIRECT_URI).is_registered() is True

    @responses.activate
    def test_register(self):
        registration_endpoint = self.PROVIDER_BASEURL + '/register'
        redirect_uris = ['https://client.example.com/redirect']
        post_logout_redirect_uris = ['https://client.example.com/logout']
        client_registration_response = {
            'client_id': 'client1',
            'client_secret': 'secret1',
            'client_name': 'Test Client',
            'redirect_uris': redirect_uris,
            'post_logout_redirect_uris': post_logout_redirect_uris
        }
        responses.add(responses.POST, registration_endpoint, json=client_registration_response)

        provider_metadata = self.PROVIDER_METADATA.copy(registration_endpoint=registration_endpoint)
        unregistered = ProviderConfiguration(provider_metadata=provider_metadata,
                                             client_registration_info=ClientRegistrationInfo(
                                                 redirect_uris=redirect_uris,
                                                 post_logout_redirect_uris=post_logout_redirect_uris
                                             ))
        facade = PyoidcFacade(unregistered, REDIRECT_URI)
        facade.register()
        assert facade.is_registered() is True

    def test_authentication_request(self):
        extra_user_auth_params = {'foo': 'bar', 'abc': 'xyz'}
        config = ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                       client_metadata=self.CLIENT_METADATA,
                                       auth_request_params=extra_user_auth_params)

        state = 'test_state'
        nonce = 'test_nonce'

        facade = PyoidcFacade(config, REDIRECT_URI)
        extra_lib_auth_params = {'foo': 'baz', 'qwe': 'rty'}
        auth_request = facade.authentication_request(state, nonce, extra_lib_auth_params)

        expected_auth_params = {
            'scope': 'openid',
            'response_type': 'code',
            'client_id': self.CLIENT_METADATA['client_id'],
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'nonce': nonce
        }
        expected_auth_params.update(extra_user_auth_params)
        expected_auth_params.update(extra_lib_auth_params)
        assert auth_request.to_dict() == expected_auth_params

    def test_parse_authentication_response(self):
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        auth_code = 'auth_code-1234'
        state = 'state-1234'
        auth_response = AuthorizationResponse(**{'state': state, 'code': auth_code})
        parsed_auth_response = facade.parse_authentication_response(auth_response.to_dict())
        assert isinstance(parsed_auth_response, AuthorizationResponse)
        assert parsed_auth_response.to_dict() == auth_response.to_dict()

    def test_parse_authentication_response_handles_error_response(self):
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        error_response = AuthorizationErrorResponse(**{'error': 'invalid_request', 'state': 'state-1234'})
        parsed_auth_response = facade.parse_authentication_response(error_response)
        assert isinstance(parsed_auth_response, AuthorizationErrorResponse)
        assert parsed_auth_response.to_dict() == error_response.to_dict()

    @responses.activate
    def test_parse_authentication_response_preserves_id_token_jwt(self):
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        state = 'state-1234'
        now = int(time.time())
        id_token, id_token_signing_key = signed_id_token({
            'iss': self.PROVIDER_METADATA['issuer'],
            'sub': 'test_sub',
            'aud': 'client1',
            'exp': now + 1,
            'iat': now
        })
        responses.add(responses.GET,
                      self.PROVIDER_METADATA['jwks_uri'],
                      json={'keys': [id_token_signing_key.serialize()]})
        auth_response = AuthorizationResponse(**{'state': state, 'id_token': id_token})
        parsed_auth_response = facade.parse_authentication_response(auth_response)
        assert isinstance(parsed_auth_response, AuthorizationResponse)
        assert parsed_auth_response['state'] == state
        assert parsed_auth_response['id_token_jwt'] == id_token

    @pytest.mark.parametrize('request_func, expected_token_request', [
        (
                lambda facade: facade.exchange_authorization_code('auth-code', 'test-state', {}),
                {
                    'grant_type': 'authorization_code',
                    'state': 'test-state',
                    'redirect_uri': REDIRECT_URI
                }
        ),
        (
                lambda facade: facade.refresh_token('refresh-token'),
                {
                    'grant_type': 'refresh_token',
                    'refresh_token': 'refresh-token',
                    'redirect_uri': REDIRECT_URI
                }
        )
    ])
    @responses.activate
    def test_token_request(self, request_func, expected_token_request):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        now = int(time.time())
        id_token_claims = {
            'iss': self.PROVIDER_METADATA['issuer'],
            'sub': 'test_user',
            'aud': [self.CLIENT_METADATA['client_id']],
            'exp': now + 1,
            'iat': now,
            'nonce': 'test_nonce'
        }
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)
        token_response = AccessTokenResponse(access_token='test_access_token',
                                             refresh_token='refresh-token',
                                             token_type='Bearer',
                                             id_token=id_token_jwt,
                                             expires_in=now + 1)

        responses.add(responses.POST, token_endpoint, json=token_response.to_dict())

        provider_metadata = self.PROVIDER_METADATA.copy(token_endpoint=token_endpoint)
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=provider_metadata,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        grant = Grant(resp=token_response)
        grant.grant_expiration_time = now + grant.exp_in
        facade._client.grant = {'test-state': grant}

        responses.add(responses.GET,
                      self.PROVIDER_METADATA['jwks_uri'],
                      json={'keys': [id_token_signing_key.serialize()]})
        token_response = request_func(facade)

        assert isinstance(token_response, AccessTokenResponse)
        expected_token_response = token_response.to_dict()
        expected_token_response['id_token'] = id_token_claims
        expected_token_response['id_token_jwt'] = id_token_jwt
        assert token_response.to_dict() == expected_token_response

        token_request = dict(parse_qsl(responses.calls[0].request.body))
        assert token_request == expected_token_request

    @responses.activate
    def test_token_request_handles_error_response(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        token_response = TokenErrorResponse(error='invalid_request', error_description='test error description')
        responses.add(responses.POST, token_endpoint, json=token_response.to_dict(), status=400)

        provider_metadata = self.PROVIDER_METADATA.copy(token_endpoint=token_endpoint)
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=provider_metadata,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        state = 'test-state'
        grant = Grant()
        grant.grant_expiration_time = int(time.time()) + grant.exp_in
        facade._client.grant = {state: grant}
        assert facade.exchange_authorization_code('1234', state, {}) == token_response

    def test_token_request_handles_missing_provider_token_endpoint(self):
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        assert facade.exchange_authorization_code(None, None, {}) is None

    @pytest.mark.parametrize('userinfo_http_method', [
        'GET',
        'POST'
    ])
    @responses.activate
    def test_configurable_userinfo_endpoint_method_is_used(self, userinfo_http_method):
        userinfo_endpoint = self.PROVIDER_BASEURL + '/userinfo'
        userinfo_response = OpenIDSchema(sub='user1')
        responses.add(userinfo_http_method, userinfo_endpoint, json=userinfo_response.to_dict())

        provider_metadata = self.PROVIDER_METADATA.copy(userinfo_endpoint=userinfo_endpoint)
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=provider_metadata,
                                                    client_metadata=self.CLIENT_METADATA,
                                                    userinfo_http_method=userinfo_http_method),
                              REDIRECT_URI)
        assert facade.userinfo_request('test_token') == userinfo_response

    def test_no_userinfo_request_is_made_if_no_userinfo_http_method_is_configured(self):
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=self.CLIENT_METADATA,
                                                    userinfo_http_method=None),
                              REDIRECT_URI)
        assert facade.userinfo_request('test_token') is None

    def test_no_userinfo_request_is_made_if_no_userinfo_endpoint_is_configured(self):
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        assert facade.userinfo_request('test_token') is None

    def test_no_userinfo_request_is_made_if_no_access_token(self):
        provider_metadata = self.PROVIDER_METADATA.copy(userinfo_endpoint=self.PROVIDER_BASEURL + '/userinfo')
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=provider_metadata,
                                                    client_metadata=self.CLIENT_METADATA),
                              REDIRECT_URI)
        assert facade.userinfo_request(None) is None

    @responses.activate
    @pytest.mark.parametrize('scope, extra_args',
                             [(None, {}),
                              (['read', 'write'],
                               {'audience': ['client_id1, client_id2']})
                              ])
    def test_client_credentials_grant(self, scope, extra_args):
        token_endpoint = f'{self.PROVIDER_BASEURL}/token'
        provider_metadata = self.PROVIDER_METADATA.copy(
            token_endpoint=token_endpoint)
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=provider_metadata,
                client_metadata=self.CLIENT_METADATA),
            REDIRECT_URI)
        client_credentials_grant_response = {
            'access_token': 'access_token',
            'expires_in': 60,
            'not-before-policy': 0,
            'refresh_expires_in': 0,
            'scope': 'read write',
            'token_type': 'Bearer'}
        responses.add(responses.POST, token_endpoint,
                      json=client_credentials_grant_response)
        assert client_credentials_grant_response == facade.client_credentials_grant(
            scope=scope, **extra_args).to_dict()

    def test_post_logout_redirect_uris(self):
        post_logout_redirect_uris = ['https://client.example.com/logout']
        client_metadata = self.CLIENT_METADATA.copy(
            post_logout_redirect_uris=post_logout_redirect_uris)
        facade = PyoidcFacade(ProviderConfiguration(provider_metadata=self.PROVIDER_METADATA,
                                                    client_metadata=client_metadata),
                              REDIRECT_URI)
        assert facade.post_logout_redirect_uris == post_logout_redirect_uris
