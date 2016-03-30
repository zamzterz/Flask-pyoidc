import json

import time
from six.moves.urllib.parse import parse_qsl, urlparse

from mock import MagicMock

import flask
import pytest
import responses
from flask import Flask
from oic.oic.message import IdToken

from flask_pyoidc.flask_pyoidc import OIDCAuthentication

ISSUER = 'https://op.example.com'


class TestOIDCAuthentication(object):
    @pytest.fixture(autouse=True)
    def create_flask_app(self):
        self.app = Flask(__name__)
        self.app.config.update({'SERVER_NAME': 'localhost',
                                'SECRET_KEY': 'test_key'})

    @responses.activate
    def test_store_internal_redirect_uri_on_static_client_reg(self):
        responses.add(responses.GET, ISSUER + '/.well-known/openid-configuration',
                      body=json.dumps(dict(issuer=ISSUER, token_endpoint=ISSUER + '/token')),
                      content_type='application/json')

        authn = OIDCAuthentication(self.app, issuer=ISSUER,
                                   client_registration_info=dict(client_id='abc',
                                                                 client_secret='foo'))
        assert len(authn.client.registration_response['redirect_uris']) == 1
        assert authn.client.registration_response['redirect_uris'][
                   0] == 'http://localhost/redirect_uri'

    @pytest.mark.parametrize('method', [
        'GET',
        'POST'
    ])
    def test_configurable_userinfo_endpoint_method_is_used(self, method):
        state = 'state'
        nonce = 'nonce'
        sub = 'foobar'
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER,
                                                                          'token_endpoint': '/token'},
                                   client_registration_info={'client_id': 'foo'},
                                   userinfo_endpoint_method=method)
        authn.client.do_access_token_request = MagicMock(
                return_value={'id_token': IdToken(**{'sub': sub, 'nonce': nonce}),
                              'access_token': 'access_token'})
        authn.callback = MagicMock()
        userinfo_request_mock = MagicMock(return_value={'sub': sub})
        authn.client.do_user_info_request = userinfo_request_mock
        with self.app.test_request_context('/redirect_uri?code=foo&state=' + state):
            flask.session['state'] = state
            flask.session['nonce'] = nonce
            authn._handle_authentication_response()
        userinfo_request_mock.assert_called_with(method=method, state=state)

    def test_no_userinfo_request_is_done_if_no_userinfo_endpoint_method_is_specified(self):
        state = 'state'
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER},
                                   client_registration_info={'client_id': 'foo'},
                                   userinfo_endpoint_method=None)
        userinfo_request_mock = MagicMock()
        authn.client.do_user_info_request = userinfo_request_mock
        authn._do_userinfo_request(state, None)
        assert not userinfo_request_mock.called

    def test_authenticatate_with_extra_request_parameters(self):
        extra_params = {"foo": "bar", "abc": "xyz"}
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER},
                                   client_registration_info={'client_id': 'foo'},
                                   extra_request_args=extra_params)

        with self.app.test_request_context('/'):
            a = authn._authenticate()
        request_params = dict(parse_qsl(urlparse(a.location).query))
        assert set(extra_params.items()).issubset(set(request_params.items()))

    def test_reauthentication_necessary_with_None(self):
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER},
                                   client_registration_info={'client_id': 'foo'})
        assert authn._reauthentication_necessary(None) is True

    def test_reauthentication_necessary_with_valid_id_token(self):
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER},
                                   client_registration_info={'client_id': 'foo'})
        test_time = 20
        id_token = {'exp': test_time + 1}
        assert authn._reauthentication_necessary(id_token, now=test_time) is False

    def test_reauthentication_necessary_with_expired_id_token(self):
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER},
                                   client_registration_info={'client_id': 'foo'})
        test_time = 20
        id_token = {'exp': test_time - 1}
        assert authn._reauthentication_necessary(id_token, now=test_time) is True

    def test_dont_reauthenticate_with_valid_id_token(self):
        authn = OIDCAuthentication(self.app, provider_configuration_info={'issuer': ISSUER},
                                   client_registration_info={'client_id': 'foo'})
        client_mock = MagicMock()
        callback_mock = MagicMock()
        authn.client = client_mock
        authn.callback = callback_mock
        with self.app.test_request_context('/'):
            flask.g.id_token = {'exp': time.time() + 25}
            authn._authenticate()
        assert not client_mock.construct_AuthorizationRequest.called
        assert callback_mock.called is True