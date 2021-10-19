import json
import logging

import flask
import pytest
import responses
import time
from datetime import datetime
from flask import Flask
from flask_pyoidc.redirect_uri_config import RedirectUriConfig
from http.cookies import SimpleCookie
from jwkest import jws
from oic.oic import AuthorizationResponse
from oic.oic.message import IdToken
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlparse, urlencode

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata, \
    ClientRegistrationInfo
from flask_pyoidc.user_session import UserSession
from .util import signed_id_token


class TestOIDCAuthentication(object):
    PROVIDER_BASEURL = 'https://op.example.com'
    PROVIDER_NAME = 'test_provider'
    CLIENT_ID = 'client1'
    CLIENT_DOMAIN = 'client.example.com'
    CALLBACK_RETURN_VALUE = 'callback called successfully'

    @pytest.fixture(autouse=True)
    def create_flask_app(self):
        self.app = Flask(__name__)
        self.app.config.update({'SERVER_NAME': self.CLIENT_DOMAIN, 'SECRET_KEY': 'test_key'})

    def init_app(self, provider_metadata_extras=None, client_metadata_extras=None, **kwargs):
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

        provider_configurations = {self.PROVIDER_NAME: ProviderConfiguration(provider_metadata=provider_metadata,
                                                                             client_metadata=client_metadata,
                                                                             **kwargs)}
        authn = OIDCAuthentication(provider_configurations)
        authn.init_app(self.app)
        return authn

    def get_view_mock(self):
        mock = MagicMock()
        mock.__name__ = 'test_callback'
        mock.return_value = self.CALLBACK_RETURN_VALUE
        return mock

    def assert_auth_redirect(self, auth_redirect):
        assert auth_redirect.status_code == 302
        assert auth_redirect.location.startswith(self.PROVIDER_BASEURL)

    def assert_view_mock(self, callback_mock, result):
        assert callback_mock.called
        assert result == self.CALLBACK_RETURN_VALUE

    def test_explicit_redirect_uri_config_should_be_preferred(self):
        redirect_uri_config = RedirectUriConfig('https://example.com/abc/redirect_uri', 'redirect_uri')
        assert OIDCAuthentication({}, self.app, redirect_uri_config)._redirect_uri_config == redirect_uri_config

    def test_explicit_redirect_uri_config_should_be_preserved_after_init_app(self):
        redirect_uri_config = RedirectUriConfig('https://example.com/abc/redirect_uri', 'redirect_uri')
        authn = OIDCAuthentication({}, None, redirect_uri_config)
        assert authn._redirect_uri_config == redirect_uri_config
        authn.init_app(self.app)
        assert authn._redirect_uri_config == redirect_uri_config

    def test_should_authenticate_if_no_session(self):
        authn = self.init_app()
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            auth_redirect = authn.oidc_auth(self.PROVIDER_NAME)(view_mock)()

        self.assert_auth_redirect(auth_redirect)
        assert not view_mock.called

    def test_should_not_authenticate_if_session_exists(self):
        authn = self.init_app()
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            UserSession(flask.session, self.PROVIDER_NAME).update()
            result = authn.oidc_auth(self.PROVIDER_NAME)(view_mock)()
        self.assert_view_mock(view_mock, result)

    def test_reauthenticate_silent_if_session_expired(self):
        authn = self.init_app(session_refresh_interval_seconds=1)
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            now = time.time()
            with patch('time.time') as time_mock:
                time_mock.return_value = now - 1  # authenticated in the past
                UserSession(flask.session, self.PROVIDER_NAME).update()
            auth_redirect = authn.oidc_auth(self.PROVIDER_NAME)(view_mock)()

        self.assert_auth_redirect(auth_redirect)
        assert 'prompt=none' in auth_redirect.location  # ensure silent auth is used
        assert not view_mock.called

    def test_dont_reauthenticate_silent_if_session_not_expired(self):
        authn = self.init_app(session_refresh_interval_seconds=999)
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            UserSession(flask.session, self.PROVIDER_NAME).update()  # freshly authenticated
            result = authn.oidc_auth(self.PROVIDER_NAME)(view_mock)()
        self.assert_view_mock(view_mock, result)

    @pytest.mark.parametrize('response_type,expected', [
        ('code', False),
        ('id_token token', True)
    ])
    def test_expected_auth_response_mode_is_set(self, response_type, expected):
        authn = self.init_app(auth_request_params={'response_type': response_type})
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            auth_redirect = authn.oidc_auth(self.PROVIDER_NAME)(view_mock)()
            assert flask.session['fragment_encoded_response'] is expected
        self.assert_auth_redirect(auth_redirect)

    @responses.activate
    @pytest.mark.parametrize('post_logout_redirect_uris', [
        None,
        ['https://example.com/post_logout']
    ])
    def test_should_register_client_if_not_registered_before(self, post_logout_redirect_uris):
        registration_endpoint = self.PROVIDER_BASEURL + '/register'
        provider_metadata = ProviderMetadata(self.PROVIDER_BASEURL,
                                             self.PROVIDER_BASEURL + '/auth',
                                             self.PROVIDER_BASEURL + '/jwks',
                                             registration_endpoint=registration_endpoint)
        client_metadata = {}
        if post_logout_redirect_uris:
            client_metadata['post_logout_redirect_uris'] = post_logout_redirect_uris
        provider_configurations = {
            self.PROVIDER_NAME: ProviderConfiguration(provider_metadata=provider_metadata,
                                                      client_registration_info=ClientRegistrationInfo(**client_metadata))
        }
        authn = OIDCAuthentication(provider_configurations)
        authn.init_app(self.app)

        # register logout view to force 'post_logout_redirect_uris' to be included in registration request
        logout_view_mock = self.get_view_mock()
        self.app.add_url_rule('/logout', view_func=logout_view_mock)
        authn.oidc_logout(logout_view_mock)

        responses.add(responses.POST, registration_endpoint, json={'client_id': 'client1', 'client_secret': 'secret1'})
        view_mock = self.get_view_mock()
        with self.app.test_request_context('/'):
            auth_redirect = authn.oidc_auth(self.PROVIDER_NAME)(view_mock)()

        self.assert_auth_redirect(auth_redirect)
        registration_request = json.loads(responses.calls[0].request.body.decode('utf-8'))
        expected_post_logout_redirect_uris = post_logout_redirect_uris if post_logout_redirect_uris else ['http://{}/logout'.format(self.CLIENT_DOMAIN)]
        expected_registration_request = {
            'redirect_uris': ['http://{}/redirect_uri'.format(self.CLIENT_DOMAIN)],
            'post_logout_redirect_uris': expected_post_logout_redirect_uris
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
        id_token_claims = {
            'iss': self.PROVIDER_BASEURL,
            'aud': [self.CLIENT_ID],
            'sub': user_id,
            'exp': int(timestamp) + exp_time,
            'iat': int(timestamp),
            'nonce': nonce
        }
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)
        access_token = 'test_access_token'
        expires_in = 3600
        token_response = {
            'access_token': access_token,
            'expires_in': expires_in,
            'token_type': 'Bearer',
            'id_token': id_token_jwt
        }
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        responses.add(responses.POST, token_endpoint, json=token_response)
        responses.add(responses.GET,
                      self.PROVIDER_BASEURL + '/jwks',
                      json={'keys': [id_token_signing_key.serialize()]})

        # mock userinfo response
        userinfo = {'sub': user_id, 'name': 'Test User'}
        userinfo_endpoint = self.PROVIDER_BASEURL + '/userinfo'
        responses.add(responses.GET, userinfo_endpoint, json=userinfo)

        authn = self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint,
                                                        'userinfo_endpoint': userinfo_endpoint})
        state = 'test_state'
        with self.app.test_request_context('/redirect_uri?state={}&code=test'.format(state)):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['destination'] = '/'
            flask.session['auth_request'] = json.dumps({'state': state, 'nonce': nonce})
            authn._handle_authentication_response()
            session = UserSession(flask.session)
            assert session.access_token == access_token
            assert session.access_token_expires_at == int(timestamp) + expires_in
            assert session.id_token == id_token_claims
            assert session.id_token_jwt == id_token_jwt
            assert session.userinfo == userinfo

    @patch('time.time')
    @patch('oic.utils.time_util.utc_time_sans_frac')  # used internally by pyoidc when verifying ID Token
    @responses.activate
    def test_handle_implicit_authentication_response(self, time_mock, utc_time_sans_frac_mock):
        # freeze time since ID Token validation includes expiration timestamps
        timestamp = time.mktime(datetime(2017, 1, 1).timetuple())
        time_mock.return_value = timestamp
        utc_time_sans_frac_mock.return_value = int(timestamp)

        # mock auth response
        access_token = 'test_access_token'
        user_id = 'user1'
        exp_time = 10
        nonce = 'test_nonce'
        id_token_claims = {
            'iss': self.PROVIDER_BASEURL,
            'aud': [self.CLIENT_ID],
            'sub': user_id,
            'exp': int(timestamp) + exp_time,
            'iat': int(timestamp),
            'nonce': nonce,
            'at_hash': jws.left_hash(access_token)
        }
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)

        responses.add(responses.GET,
                      self.PROVIDER_BASEURL + '/jwks',
                      json={'keys': [id_token_signing_key.serialize()]})

        # mock userinfo response
        userinfo = {'sub': user_id, 'name': 'Test User'}
        userinfo_endpoint = self.PROVIDER_BASEURL + '/userinfo'
        responses.add(responses.GET, userinfo_endpoint, json=userinfo)

        authn = self.init_app(provider_metadata_extras={'userinfo_endpoint': userinfo_endpoint})
        state = 'test_state'
        auth_response = AuthorizationResponse(
            **{'state': state, 'access_token': access_token, 'token_type': 'Bearer', 'id_token': id_token_jwt})

        with self.app.test_client() as client:
            with client.session_transaction() as session:
                UserSession(session, self.PROVIDER_NAME)
                session['destination'] = '/'
                session['auth_request'] = json.dumps({'state': state, 'nonce': nonce})
                session['fragment_encoded_response'] = True
            client.get('/redirect_uri#{}'.format(auth_response.to_urlencoded()))
            assert 'auth_request' in session  # stored auth_request should not have been removed yet

            # fake the POST request from the 'parse_fragment.html' template
            resp = client.post('/redirect_uri', data=auth_response.to_dict())
            user_session = UserSession(flask.session)
            assert user_session.access_token == access_token
            assert user_session.id_token == id_token_claims
            assert user_session.id_token_jwt == id_token_jwt
            assert user_session.userinfo == userinfo
            assert 'auth_request' not in flask.session  # stored auth_request should have been removed now
            assert resp.data.decode('utf-8') == '/'  # final redirect back to the protected endpoint

    def test_handle_authentication_response_POST(self):
        access_token = 'test_access_token'
        state = 'test_state'

        authn = self.init_app()
        auth_response = AuthorizationResponse(**{'state': state, 'token_type': 'Bearer', 'access_token': access_token})

        with self.app.test_request_context('/redirect_uri',
                                           method='POST',
                                           data=auth_response.to_dict(),
                                           mimetype='application/x-www-form-urlencoded'):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['destination'] = '/test'
            flask.session['auth_request'] = json.dumps({'state': state, 'nonce': 'test_nonce'})
            response = authn._handle_authentication_response()
            session = UserSession(flask.session)
            assert session.access_token == access_token
            assert response == '/test'

    def test_handle_error_response_POST(self):
        state = 'test_state'

        authn = self.init_app()
        error_resp = {'state': state, 'error': 'invalid_request', 'error_description': 'test error'}

        with self.app.test_request_context('/redirect_uri',
                                           method='POST',
                                           data=error_resp,
                                           mimetype='application/x-www-form-urlencoded'):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['auth_request'] = json.dumps({'state': state, 'nonce': 'test_nonce'})
            response = authn._handle_authentication_response()
            assert flask.session['error'] == error_resp
            assert response == '/redirect_uri?error=1'


    def test_handle_authentication_response_without_initialised_session(self):
        authn = self.init_app()

        with self.app.test_request_context('/redirect_uri?state=test-state&code=test'):
            response = authn._handle_authentication_response()
            assert response == 'Something went wrong with the authentication, please try to login again.'

            # with error view configured, error object should be sent to it instead
            error_view_mock = self.get_view_mock()
            authn.error_view(error_view_mock)
            result = authn._handle_authentication_response()
            self.assert_view_mock(error_view_mock, result)
            error_view_mock.assert_called_with(**{'error': 'unsolicited_response', 'error_description': 'No initialised user session.'})

    def test_handle_authentication_response_without_stored_auth_request(self):
        authn = self.init_app()

        with self.app.test_request_context('/redirect_uri?state=test-state&code=test'):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['destination'] = '/test'
            response = authn._handle_authentication_response()
            assert response == 'Something went wrong with the authentication, please try to login again.'

            # with error view configured, error object should be sent to it instead
            error_view_mock = self.get_view_mock()
            authn.error_view(error_view_mock)
            result = authn._handle_authentication_response()
            self.assert_view_mock(error_view_mock, result)
            error_view_mock.assert_called_with(**{'error': 'unsolicited_response', 'error_description': 'No authentication request stored.'})

    def test_handle_authentication_response_fragment_encoded(self):
        authn = self.init_app()
        with self.app.test_request_context('/redirect_uri'):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['auth_request'] = json.dumps({'state': 'test_state', 'nonce': 'test_nonce'})
            flask.session['fragment_encoded_response'] = True
            response = authn._handle_authentication_response()
        assert response.startswith('<html>')

    def test_handle_authentication_response_error_message(self):
        authn = self.init_app()
        with self.app.test_request_context('/redirect_uri?error=1'):
            flask.session['error'] = {'error': 'test'}
            response = authn._handle_authentication_response()
        assert response == 'Something went wrong with the authentication, please try to login again.'

    def test_handle_authentication_response_error_message_without_stored_error(self):
        authn = self.init_app()
        with self.app.test_request_context('/redirect_uri?error=1'):
            response = authn._handle_authentication_response()
        assert response == 'Something went wrong.'

    @patch('time.time')
    @patch('oic.utils.time_util.utc_time_sans_frac')  # used internally by pyoidc when verifying ID Token
    @responses.activate
    def test_session_expiration_set_to_configured_lifetime(self, time_mock, utc_time_sans_frac_mock):
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

        session_lifetime = 1234
        self.app.config['PERMANENT_SESSION_LIFETIME'] = session_lifetime
        self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint})

        with self.app.test_client() as client:
            with client.session_transaction() as session:
                UserSession(session, self.PROVIDER_NAME)
                session['destination'] = '/'
                session['auth_request'] = json.dumps({'state': state, 'nonce': nonce, 'response_type': 'code'})
            resp = client.get('/redirect_uri?state={}&code=test'.format(state))

        cookies = SimpleCookie()
        cookies.load(resp.headers['Set-Cookie'])
        session_cookie_expiration = cookies[self.app.config['SESSION_COOKIE_NAME']]['expires']
        parsed_expiration = datetime.strptime(session_cookie_expiration, '%a, %d %b %Y %H:%M:%S GMT')
        cookie_lifetime = (parsed_expiration - datetime.utcnow()).total_seconds()
        assert cookie_lifetime == pytest.approx(session_lifetime, abs=1)

    @pytest.mark.parametrize('post_logout_redirect_uri', [
        None,
        'https://example.com/post_logout'
    ])
    def test_logout_redirects_to_provider_if_end_session_endpoint_is_configured(self, post_logout_redirect_uri):
        end_session_endpoint = 'https://provider.example.com/end_session'
        client_metadata = {}
        if post_logout_redirect_uri:
            client_metadata['post_logout_redirect_uris'] = [post_logout_redirect_uri]

        authn = self.init_app(provider_metadata_extras={'end_session_endpoint': end_session_endpoint},
                              client_metadata_extras=client_metadata)
        logout_view_mock = self.get_view_mock()
        id_token = IdToken(**{'sub': 'sub1', 'nonce': 'nonce'})

        # register logout view
        view_func = authn.oidc_logout(logout_view_mock)
        self.app.add_url_rule('/logout', view_func=view_func)

        with self.app.test_request_context('/logout'):
            UserSession(flask.session, self.PROVIDER_NAME).update(access_token='test_access_token',
                                                                  id_token=id_token.to_dict(),
                                                                  id_token_jwt=id_token.to_jwt(),
                                                                  userinfo={'sub': 'user1'})
            end_session_redirect = view_func()
            # ensure user session has been cleared
            assert all(k not in flask.session for k in UserSession.KEYS)
            parsed_request = dict(parse_qsl(urlparse(end_session_redirect.headers['Location']).query))
            assert parsed_request['state'] == flask.session['end_session_state']

        assert end_session_redirect.status_code == 303
        assert end_session_redirect.location.startswith(end_session_endpoint)
        assert IdToken().from_jwt(parsed_request['id_token_hint']) == id_token

        expected_post_logout_redirect_uri = post_logout_redirect_uri if post_logout_redirect_uri else 'http://{}/logout'.format(self.CLIENT_DOMAIN)
        assert parsed_request['post_logout_redirect_uri'] == expected_post_logout_redirect_uri
        assert not logout_view_mock.called

    def test_logout_with_missing_end_session_state_fails_gracefully(self):
        end_session_endpoint = 'https://provider.example.com/end_session'
        authn = self.init_app(provider_metadata_extras={'end_session_endpoint': end_session_endpoint})
        id_token = IdToken(**{'sub': 'sub1', 'nonce': 'nonce'})
        logout_view_mock = self.get_view_mock()

        # register logout view
        view_func = authn.oidc_logout(logout_view_mock)
        self.app.add_url_rule('/logout', view_func=view_func)

        with self.app.test_request_context('/logout?state=incorrect'):
            UserSession(flask.session, self.PROVIDER_NAME).update(access_token='test_access_token',
                                                                  id_token=id_token.to_dict(),
                                                                  id_token_jwt=id_token.to_jwt(),
                                                                  userinfo={'sub': 'user1'})
            flask.session.pop('end_session_state', None)  # make sure there's no 'end_session_state'
            logout_result = authn.oidc_logout(logout_view_mock)()

        self.assert_view_mock(logout_view_mock, logout_result)

    def test_logout_handles_provider_without_end_session_endpoint(self):
        authn = self.init_app()
        id_token = IdToken(**{'sub': 'sub1', 'nonce': 'nonce'})
        logout_view_mock = self.get_view_mock()
        with self.app.test_request_context('/logout'):
            UserSession(flask.session, self.PROVIDER_NAME).update(access_token='test_access_token',
                                                                  id_token=id_token.to_dict(),
                                                                  id_token_jwt=id_token.to_jwt(),
                                                                  userinfo={'sub': 'user1'})

            logout_result = authn.oidc_logout(logout_view_mock)()
            assert all(k not in flask.session for k in UserSession.KEYS)

        self.assert_view_mock(logout_view_mock, logout_result)

    def test_logout_handles_redirect_back_from_provider(self):
        authn = self.init_app()
        logout_view_mock = self.get_view_mock()
        state = 'end_session_123'
        with self.app.test_request_context('/logout?state={}'.format(state)):
            flask.session['end_session_state'] = state
            result = authn.oidc_logout(logout_view_mock)()
            assert 'end_session_state' not in flask.session

        self.assert_view_mock(logout_view_mock, result)

    def test_logout_handles_redirect_back_from_provider_with_incorrect_state(self, caplog):
        authn = self.init_app()
        logout_view_mock = self.get_view_mock()
        state = 'some_state'
        with self.app.test_request_context('/logout?state={}'.format(state)):
            flask.session['end_session_state'] = 'other_state'
            result = authn.oidc_logout(logout_view_mock)()
            assert 'end_session_state' not in flask.session

        self.assert_view_mock(logout_view_mock, result)
        assert caplog.record_tuples[-1] == ('flask_pyoidc.flask_pyoidc',
                                            logging.ERROR,
                                            "Got unexpected state '{}' after logout redirect.".format(state))

    def test_logout_handles_no_user_session(self):
        authn = self.init_app()
        logout_view_mock = self.get_view_mock()
        with self.app.test_request_context('/logout'):
            result = authn.oidc_logout(logout_view_mock)()

        self.assert_view_mock(logout_view_mock, result)

    def test_authentication_error_response_calls_to_error_view_if_set(self):
        state = 'test_tate'
        error_response = {'error': 'invalid_request', 'error_description': 'test error'}
        authn = self.init_app()
        error_view_mock = self.get_view_mock()
        authn.error_view(error_view_mock)
        with self.app.test_request_context('/redirect_uri?{error}&state={state}'.format(error=urlencode(error_response),
                                                                                        state=state)):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['auth_request'] = json.dumps({'state': state, 'nonce': 'test_nonce'})
            result = authn._handle_authentication_response()

        self.assert_view_mock(error_view_mock, result)
        error_view_mock.assert_called_with(**error_response)

    def test_authentication_error_response_returns_default_error_if_no_error_view_set(self):
        state = 'test_tate'
        error_response = {'error': 'invalid_request', 'error_description': 'test error', 'state': state}
        authn = self.init_app(dict(provider_configuration_info={'issuer': self.PROVIDER_BASEURL},
                                   client_registration_info=dict(client_id='abc', client_secret='foo')))
        with self.app.test_request_context('/redirect_uri?{}'.format(urlencode(error_response))):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['state'] = state
            flask.session['nonce'] = 'test_nonce'
            response = authn._handle_authentication_response()
        assert response == "Something went wrong with the authentication, please try to login again."

    @responses.activate
    def test_token_error_response_calls_to_error_view_if_set(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        error_response = {'error': 'invalid_request', 'error_description': 'test error'}
        responses.add(responses.POST, token_endpoint, json=error_response)

        authn = self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint})
        error_view_mock = self.get_view_mock()
        authn.error_view(error_view_mock)
        state = 'test_tate'
        with self.app.test_request_context('/redirect_uri?code=foo&state={}'.format(state)):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['auth_request'] = json.dumps({'state': state, 'nonce': 'test_nonce'})
            result = authn._handle_authentication_response()

        self.assert_view_mock(error_view_mock, result)
        error_view_mock.assert_called_with(**error_response)

    @responses.activate
    def test_token_error_response_returns_default_error_if_no_error_view_set(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        state = 'test_tate'
        error_response = {'error': 'invalid_request', 'error_description': 'test error', 'state': state}
        responses.add(responses.POST, token_endpoint, json=error_response)

        authn = self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint})
        with self.app.test_request_context('/redirect_uri?code=foo&state=' + state):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session['state'] = state
            flask.session['nonce'] = 'test_nonce'
            response = authn._handle_authentication_response()
        assert response == "Something went wrong with the authentication, please try to login again."

    def test_using_unknown_provider_name_should_raise_exception(self):
        with pytest.raises(ValueError) as exc_info:
            self.init_app().oidc_auth('unknown')
        assert 'unknown' in str(exc_info.value)

    def test_should_not_refresh_if_no_user_session(self):
        with self.app.test_request_context('/foo'):
            assert self.init_app().valid_access_token() is None

    @responses.activate
    def test_should_refresh_expired_access_token(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        authn = self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint})

        token_response = {
            'access_token': 'new-access-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'refresh_token': 'new-refresh-token'
        }
        responses.add(responses.POST, token_endpoint, json=token_response)

        with self.app.test_request_context('/foo'):
            session = UserSession(flask.session, self.PROVIDER_NAME)
            session.update(expires_in=-10, refresh_token='refresh-token')
            assert authn.valid_access_token() == token_response['access_token']
            assert session.access_token == token_response['access_token']
            assert session.refresh_token == token_response['refresh_token']

    def test_should_not_refresh_still_valid_access_token(self):
        authn = self.init_app()

        access_token = 'access_token'
        with self.app.test_request_context('/foo'):
            session = UserSession(flask.session, self.PROVIDER_NAME)
            session.update(access_token=access_token, expires_in=10, refresh_token='refresh-token')
            assert authn.valid_access_token() == access_token

    @responses.activate
    def test_should_refresh_still_valid_access_token_if_forced(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        authn = self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint})

        token_response = {
            'access_token': 'new-access-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'refresh_token': 'new-refresh-token'
        }
        responses.add(responses.POST, token_endpoint, json=token_response)

        with self.app.test_request_context('/foo'):
            session = UserSession(flask.session, self.PROVIDER_NAME)
            session.update(expires_in=10, refresh_token='refresh-token')
            assert authn.valid_access_token(force_refresh=True) == token_response['access_token']
            assert session.access_token == token_response['access_token']
            assert session.refresh_token == token_response['refresh_token']

    def test_should_not_refresh_without_refresh_token(self):
        authn = self.init_app()

        with self.app.test_request_context('/foo'):
            session = UserSession(flask.session, self.PROVIDER_NAME)
            session.update(expires_in=-10)
            assert authn.valid_access_token() is None

    def test_should_not_refresh_access_token_without_expiry(self):
        authn = self.init_app()

        access_token = 'access_token'
        with self.app.test_request_context('/foo'):
            session = UserSession(flask.session, self.PROVIDER_NAME)
            session.update(access_token=access_token, refresh_token='refresh-token')
            assert authn.valid_access_token() == access_token

    @responses.activate
    def test_should_return_None_if_token_refresh_request_fails(self):
        token_endpoint = self.PROVIDER_BASEURL + '/token'
        authn = self.init_app(provider_metadata_extras={'token_endpoint': token_endpoint})

        token_response = {
            'error': 'invalid_grant',
            'error_description': 'The refresh token is invalid'
        }
        responses.add(responses.POST, token_endpoint, json=token_response)

        access_token = 'access_token'
        with self.app.test_request_context('/foo'):
            session = UserSession(flask.session, self.PROVIDER_NAME)
            session.update(access_token=access_token, expires_in=-10, refresh_token='refresh-token')
            assert authn.valid_access_token(force_refresh=True) is None
            assert session.access_token == access_token
