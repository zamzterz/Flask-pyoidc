import time

import json
import pytest
import responses
from oic.oic import IdToken
from six.moves.urllib.parse import parse_qsl, urlencode, urlparse

from example.app import ISSUER1, ISSUER2, CLIENT1, CLIENT2
from .app import app, auth


class TestExampleApp(object):
    PROVIDER1_METADATA = {
        'issuer': ISSUER1,
        'authorization_endpoint': ISSUER1 + '/auth',
        'jwks_uri': ISSUER1 + '/jwks',
        'token_endpoint': ISSUER1 + '/token',
        'userinfo_endpoint': ISSUER1 + '/userinfo'
    }
    PROVIDER2_METADATA = {
        'issuer': ISSUER2,
        'authorization_endpoint': ISSUER2 + '/auth',
        'jwks_uri': ISSUER2 + '/jwks',
        'token_endpoint': ISSUER2 + '/token',
        'userinfo_endpoint': ISSUER2 + '/userinfo'
    }
    USER_ID = 'user1'

    @pytest.fixture(scope='session', autouse=True)
    def setup(self):
        app.testing = True

        with responses.RequestsMock() as r:
            # mock provider discovery
            r.add(responses.GET, ISSUER1 + '/.well-known/openid-configuration', json=self.PROVIDER1_METADATA)
            r.add(responses.GET, ISSUER2 + '/.well-known/openid-configuration', json=self.PROVIDER2_METADATA)
            auth.init_app(app)

    @responses.activate
    def perform_authentication(self, test_client, login_endpoint, client_id, provider_metadata):
        # index page should make auth request
        auth_redirect = test_client.get(login_endpoint)
        parsed_auth_request = dict(parse_qsl(urlparse(auth_redirect.location).query))

        now = int(time.time())
        # mock token response
        id_token = IdToken(iss=provider_metadata['issuer'],
                           aud=client_id,
                           sub=self.USER_ID,
                           exp=now + 10,
                           iat=now,
                           nonce=parsed_auth_request['nonce'])
        token_response = {'access_token': 'test_access_token', 'token_type': 'Bearer', 'id_token': id_token.to_jwt()}
        responses.add(responses.POST, provider_metadata['token_endpoint'], json=token_response)

        # mock userinfo response
        userinfo = {'sub': self.USER_ID, 'name': 'Test User'}
        responses.add(responses.GET, provider_metadata['userinfo_endpoint'], json=userinfo)

        # fake auth response sent to redirect URI
        fake_auth_response = 'code=fake_auth_code&state={}'.format(parsed_auth_request['state'])
        logged_in_page = test_client.get('/redirect_uri?{}'.format(fake_auth_response), follow_redirects=True)
        result = json.loads(logged_in_page.data.decode('utf-8'))

        assert result['access_token'] == 'test_access_token'
        assert result['id_token'] == id_token.to_dict()
        assert result['userinfo'] == {'sub': self.USER_ID, 'name': 'Test User'}

    @pytest.mark.parametrize('login_endpoint, client_id, provider_metadata', [
        ('/', CLIENT1, PROVIDER1_METADATA),
        ('/login2', CLIENT2, PROVIDER2_METADATA),
    ])
    def test_login_logout(self, login_endpoint, client_id, provider_metadata):
        client = app.test_client()

        self.perform_authentication(client, login_endpoint, client_id, provider_metadata)

        response = client.get('/logout')
        assert response.data.decode('utf-8') == "You've been successfully logged out!"

    def test_error_view(self):
        client = app.test_client()

        auth_redirect = client.get('/')
        parsed_auth_request = dict(parse_qsl(urlparse(auth_redirect.location).query))

        # fake auth error response sent to redirect_uri
        error_auth_response = {
            'error': 'invalid_request',
            'error_description': 'test error',
            'state': parsed_auth_request['state']
        }
        error_page = client.get('/redirect_uri?{}'.format(urlencode(error_auth_response)), follow_redirects=True)

        assert json.loads(error_page.data.decode('utf-8')) == {
            'error': error_auth_response['error'],
            'message': error_auth_response['error_description']
        }
