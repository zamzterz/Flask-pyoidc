import time

import json
import pytest
import responses
from oic.oic import IdToken
from six.moves.urllib.parse import parse_qsl, urlencode, urlparse

from .app import app, auth, CLIENT_ID, ISSUER


class TestExampleApp(object):
    PROVIDER_METADATA = {
        'issuer': ISSUER,
        'authorization_endpoint': ISSUER + '/auth',
        'jwks_uri': ISSUER + '/jwks',
        'token_endpoint': ISSUER + '/token',
        'userinfo_endpoint': ISSUER + '/userinfo'
    }
    USER_ID = 'user1'

    @pytest.fixture('session', autouse=True)
    def setup(self):
        app.testing = True

        with responses.RequestsMock() as r:
            # mock provider discovery
            r.add(responses.GET, ISSUER + '/.well-known/openid-configuration', json=self.PROVIDER_METADATA)
            auth.init_app(app)

    @responses.activate
    def perform_authentication(self, client):
        # index page should make auth request
        auth_redirect = client.get('/')
        parsed_auth_request = dict(parse_qsl(urlparse(auth_redirect.location).query))

        now = int(time.time())
        # mock token response
        id_token = IdToken(iss=ISSUER,
                           aud=CLIENT_ID,
                           sub=self.USER_ID,
                           exp=now + 10,
                           iat=now,
                           nonce=parsed_auth_request['nonce'])
        token_response = {'access_token': 'test_access_token', 'token_type': 'Bearer', 'id_token': id_token.to_jwt()}
        responses.add(responses.POST, self.PROVIDER_METADATA['token_endpoint'], json=token_response)

        # mock userinfo response
        userinfo = {'sub': self.USER_ID, 'name': 'Test User'}
        responses.add(responses.GET, self.PROVIDER_METADATA['userinfo_endpoint'], json=userinfo)

        # fake auth response sent to redirect URI
        fake_auth_response = 'code=fake_auth_code&state={}'.format(parsed_auth_request['state'])
        logged_in_page = client.get('/redirect_uri?{}'.format(fake_auth_response), follow_redirects=True)
        result = json.loads(logged_in_page.data.decode('utf-8'))

        assert result['access_token'] == 'test_access_token'
        assert result['id_token'] == id_token.to_dict()
        assert result['userinfo'] == {'sub': self.USER_ID, 'name': 'Test User'}

    def test_login_logout(self):
        client = app.test_client()

        self.perform_authentication(client)

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
