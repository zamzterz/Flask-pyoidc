import time

import flask
import json
import pytest
import responses
from datetime import datetime
from flask import Flask
from mock import MagicMock, patch
from oic.oic.message import IdToken
from six.moves.urllib.parse import parse_qsl, urlparse, urlencode

from flask_pyoidc.flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata, \
    ClientRegistrationInfo
from flask_pyoidc.user_session import UserSession


class TestOIDCAuthentication(object):
    PROVIDER_BASEURL = 'https://op.example.com'
    CLIENT_ID = 'client1'
    CLIENT_DOMAIN = 'client.example.com'
    CALLBACK_RETURN_VALUE = 'callback called successfully'

    @pytest.fixture(autouse=True)
    def create_flask_app(self):
        self.app = Flask(__name__)
        self.app.config.update({'SERVER_NAME': self.CLIENT_DOMAIN, 'SECRET_KEY': 'test_key'})

    def get_authn_instance(self, provider_metadata_extras=None, client_metadata_extras=None, **kwargs):
        required_provider_metadata = {
            'issuer': self.PROVIDER_BASEURL,
            'authorization_endpoint': self.PROVIDER_BASEURL + '/auth',
            'jwks_uri': self.PROVIDER_BASEURL + '/jwks'
        }
        if provider_metadata_extras:
            required_provider_metadata.update(provider_metadata_extras)
        provider_metadata = ProviderMetadata(**required_provider_metadata)

        required_client_metadata = {
            'client_id': self.CLIENT_ID,
            'client_secret': 'secret1'
        }
        if client_metadata_extras:
            required_client_metadata.update(client_metadata_extras)
        client_metadata = ClientMetadata(**required_client_metadata)

        authn = OIDCAuthentication(ProviderConfiguration(provider_metadata=provider_metadata,
                                                         client_metadata=client_metadata,
                                                         **kwargs))
        authn.init_app(self.app)
        return authn

    def get_view_mock(self):
        mock = MagicMock()
        mock.__name__ = 'test_callback'  # required for Python 2
        mock.return_value = self.CALLBACK_RETURN_VALUE
        return mock

    def assert_auth_redirect(self, auth_redirect):
        assert auth_redirect.status_code == 302
        assert auth_redirect.location.startswith(self.PROVIDER_BASEURL)

    def assert_view_mock(self, callback_mock, result):
        assert callback_mock.called
        assert result == self.CALLBACK_RETURN_VALUE

    def test_should_authenticate_if_no_session(self):
        authn = self.get_authn_instance()
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            auth_redirect = authn.oidc_auth(view_mock)()

        self.assert_auth_redirect(auth_redirect)
        assert not view_mock.called

    def test_should_not_authenticate_if_session_exists(self):
        authn = self.get_authn_instance()
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            UserSession(flask.session).update(time.time())
            result = authn.oidc_auth(view_mock)()
        self.assert_view_mock(view_mock, result)

    def test_reauthenticate_silent_if_session_expired(self):
        authn = self.get_authn_instance(session_refresh_interval_seconds=1)
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            UserSession(flask.session).update(time.time() - 1)  # authenticated in the past
            auth_redirect = authn.oidc_auth(view_mock)()

        self.assert_auth_redirect(auth_redirect)
        assert 'prompt=none' in auth_redirect.location  # ensure silent auth is used
        assert not view_mock.called

    def test_dont_reauthenticate_silent_if_session_not_expired(self):
        authn = self.get_authn_instance(session_refresh_interval_seconds=999)
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            UserSession(flask.session).update(time.time())  # freshly authenticated
            result = authn.oidc_auth(view_mock)()
        self.assert_view_mock(view_mock, result)

    @responses.activate
    def test_should_register_client_if_not_registered_before(self):
        registration_endpoint = self.PROVIDER_BASEURL + '/register'
        provider_metadata = ProviderMetadata(self.PROVIDER_BASEURL,
                                             self.PROVIDER_BASEURL + '/auth',
                                             self.PROVIDER_BASEURL + '/jwks',
                                             registration_endpoint=registration_endpoint)
        authn = OIDCAuthentication(ProviderConfiguration(provider_metadata=provider_metadata,
                                                         client_registration_info=ClientRegistrationInfo()))
        authn.init_app(self.app)

        # register logout view to force 'post_logout_redirect_uris' to be included in registration request
        logout_view_mock = self.get_view_mock()
        self.app.add_url_rule('/logout', view_func=logout_view_mock)
        authn.oidc_logout(logout_view_mock)

        responses.add(responses.POST, registration_endpoint, json={'client_id': 'client1', 'client_secret': 'secret1'})
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            auth_redirect = authn.oidc_auth(view_mock)()

        self.assert_auth_redirect(auth_redirect)
        registration_request = json.loads(responses.calls[0].request.body.decode('utf-8'))
        expected_registration_request = {
            'redirect_uris': ['http://{}/redirect_uri'.format(self.CLIENT_DOMAIN)],
            'post_logout_redirect_uris': ['http://{}/logout'.format(self.CLIENT_DOMAIN)]
        }
        assert registration_request == expected_registration_request

    @patch('time.time')
    @patch('oic.utils.time_util.utc_time_sans_frac')  # used internally by pyoidc when verifying ID Token
    @responses.activate
    def test_handle_authentication_response(self, time_mock, utc_time_sans_frac_mock):
        # freeze time since ID Token validation includes expiration timestamps
        timestamp = time.mktime(datetime(2017, 1, 1).timetuple())
        time_mock.return_value = timestamp
        utc_time_sans_frac_mock.return_value = int(timestamp)

        # mock token response
        user_id = 'user1'
        exp_time = 10
        nonce = 'test_nonce'
        id_token = IdToken(iss=self.PROVIDER_BASEURL,
                           aud=self.CLIENT_ID,
                           sub=user_id,
                           exp=int(timestamp) + exp_time,
                           iat=int(timestamp),
                           nonce=nonce)
        access_token = 'test_access_token'
        token_response = {'access_token': access_token, 'token_type': 'Bearer', 'id_token': id_token.to_jwt()}
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        responses.add(responses.POST, token_endpoint, json=token_response)

        # mock userinfo response
        userinfo = {'sub': user_id, 'name': 'Test User'}
        userinfo_endpoint = self.PROVIDER_BASEURL + '/userinfo'
        responses.add(responses.GET, userinfo_endpoint, json=userinfo)

        authn = self.get_authn_instance(provider_metadata_extras={'token_endpoint': token_endpoint,
                                                                  'userinfo_endpoint': userinfo_endpoint})
        state = 'test_state'
        with self.app.test_request_context('/redirect_uri?state={}&code=test'.format(state)):
            flask.session['destination'] = '/'
            flask.session['state'] = state
            flask.session['nonce'] = nonce
            authn._handle_authentication_response()
            session = UserSession(flask.session)
            assert session.access_token == access_token
            assert session.id_token == id_token.to_dict()
            assert IdToken().from_jwt(session.id_token_jwt) == id_token
            assert session.userinfo == userinfo

    @patch('time.time')
    @patch('oic.utils.time_util.utc_time_sans_frac')  # used internally by pyoidc when verifying ID Token
    @responses.activate
    def test_session_expiration_set_to_id_token_exp(self, time_mock, utc_time_sans_frac_mock):
        timestamp = time.mktime(datetime(2017, 1, 1).timetuple())
        time_mock.return_value = timestamp
        utc_time_sans_frac_mock.return_value = int(timestamp)

        exp_time = 10
        state = 'test_state'
        nonce = 'test_nonce'
        id_token = IdToken(iss=self.PROVIDER_BASEURL,
                           aud=self.CLIENT_ID,
                           sub='sub1',
                           exp=int(timestamp) + exp_time,
                           iat=int(timestamp),
                           nonce=nonce)
        token_response = {'access_token': 'test', 'token_type': 'Bearer', 'id_token': id_token.to_jwt()}
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        responses.add(responses.POST, token_endpoint, json=token_response)

        authn = self.get_authn_instance(provider_metadata_extras={'token_endpoint': token_endpoint})
        with self.app.test_request_context('/redirect_uri?state={}&code=test'.format(state)):
            flask.session['destination'] = '/'
            flask.session['state'] = state
            flask.session['nonce'] = nonce
            authn._handle_authentication_response()
            assert flask.session.permanent
            assert int(flask.session.permanent_session_lifetime) == exp_time

    def test_logout_redirects_to_provider_if_end_session_endpoint_is_configured(self):
        end_session_endpoint = 'https://provider.example.com/end_session'
        authn = self.get_authn_instance(provider_metadata_extras={'end_session_endpoint': end_session_endpoint})
        logout_view_mock = self.get_view_mock()
        id_token = IdToken(**{'sub': 'sub1', 'nonce': 'nonce'})

        # register logout view
        self.app.add_url_rule('/logout', view_func=authn.oidc_logout(logout_view_mock))

        with self.app.test_request_context('/logout'):
            UserSession(flask.session).update(time.time(),
                                              'test_access_token',
                                              id_token.to_dict(),
                                              id_token.to_jwt(),
                                              {'sub': 'user1'})

            end_session_redirect = authn.oidc_logout(logout_view_mock)()
            # ensure user session has been cleared
            assert all(k not in flask.session for k in UserSession.KEYS)
            parsed_request = dict(parse_qsl(urlparse(end_session_redirect.headers['Location']).query))
            assert parsed_request['state'] == flask.session['end_session_state']

        assert end_session_redirect.status_code == 303
        assert end_session_redirect.location.startswith(end_session_endpoint)
        assert IdToken().from_jwt(parsed_request['id_token_hint']) == id_token
        assert parsed_request['post_logout_redirect_uri'] == 'http://{}/logout'.format(self.CLIENT_DOMAIN)
        assert not logout_view_mock.called

    def test_logout_handles_provider_without_end_session_endpoint(self):
        authn = self.get_authn_instance()
        id_token = IdToken(**{'sub': 'sub1', 'nonce': 'nonce'})
        logout_view_mock = self.get_view_mock()
        with self.app.test_request_context('/logout'):
            UserSession(flask.session).update(time.time(),
                                              'test_access_token',
                                              id_token.to_dict(),
                                              id_token.to_jwt(),
                                              {'sub': 'user1'})

            logout_result = authn.oidc_logout(logout_view_mock)()
            assert all(k not in flask.session for k in UserSession.KEYS)

        self.assert_view_mock(logout_view_mock, logout_result)

    def test_logout_handles_redirect_back_from_provider(self):
        authn = self.get_authn_instance()
        logout_view_mock = self.get_view_mock()
        state = 'end_session_123'
        with self.app.test_request_context('/logout?state={}'.format(state)):
            flask.session['end_session_state'] = state
            result = authn.oidc_logout(logout_view_mock)()
            assert 'end_session_state' not in flask.session

        self.assert_view_mock(logout_view_mock, result)

    def test_authentication_error_response_calls_to_error_view_if_set(self):
        state = 'test_tate'
        error_response = {'error': 'invalid_request', 'error_description': 'test error'}
        authn = self.get_authn_instance()
        error_view_mock = self.get_view_mock()
        authn.error_view(error_view_mock)
        with self.app.test_request_context('/redirect_uri?{error}&state={state}'.format(error=urlencode(error_response),
                                                                                        state=state)):
            flask.session['state'] = state
            result = authn._handle_authentication_response()

        self.assert_view_mock(error_view_mock, result)
        error_view_mock.assert_called_with(**error_response)

    def test_authentication_error_response_returns_default_error_if_no_error_view_set(self):
        state = 'test_tate'
        error_response = {'error': 'invalid_request', 'error_description': 'test error', 'state': state}
        authn = self.get_authn_instance(dict(provider_configuration_info={'issuer': self.PROVIDER_BASEURL},
                                             client_registration_info=dict(client_id='abc', client_secret='foo')))
        with self.app.test_request_context('/redirect_uri?{}'.format(urlencode(error_response))):
            flask.session['state'] = state
            response = authn._handle_authentication_response()
        assert response == "Something went wrong with the authentication, please try to login again."

    @responses.activate
    def test_token_error_response_calls_to_error_view_if_set(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        error_response = {'error': 'invalid_request', 'error_description': 'test error'}
        responses.add(responses.POST, token_endpoint, json=error_response)

        authn = self.get_authn_instance(provider_metadata_extras={'token_endpoint': token_endpoint})
        error_view_mock = self.get_view_mock()
        authn.error_view(error_view_mock)
        state = 'test_tate'
        with self.app.test_request_context('/redirect_uri?code=foo&state={}'.format(state)):
            flask.session['state'] = state
            result = authn._handle_authentication_response()

        self.assert_view_mock(error_view_mock, result)
        error_view_mock.assert_called_with(**error_response)

    @responses.activate
    def test_token_error_response_returns_default_error_if_no_error_view_set(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        state = 'test_tate'
        error_response = {'error': 'invalid_request', 'error_description': 'test error', 'state': state}
        responses.add(responses.POST, token_endpoint, json=error_response)

        authn = self.get_authn_instance(provider_metadata_extras={'token_endpoint': token_endpoint})
        with self.app.test_request_context('/redirect_uri?code=foo&state=' + state):
            flask.session['state'] = state
            response = authn._handle_authentication_response()
        assert response == "Something went wrong with the authentication, please try to login again."
