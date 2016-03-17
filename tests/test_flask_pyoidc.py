import json

import pytest
import responses
from flask import Flask

from flask_pyoidc.flask_pyoidc import OIDCAuthentication


class TestOIDCAuthentication(object):
    @pytest.fixture(autouse=True)
    def create_flask_app(self):
        self.app = Flask(__name__)
        self.app.config.update({'SERVER_NAME': 'localhost',
                                'SECRET_KEY': 'test_key'})

    @responses.activate
    def test_store_internal_redirect_uri_on_static_client_reg(self):
        ISSUER = 'https://op.example.com'
        responses.add(responses.GET, ISSUER + "/.well-known/openid-configuration",
                      body=json.dumps(dict(issuer=ISSUER)),
                      content_type='application/json')

        authn = OIDCAuthentication(self.app, issuer=ISSUER,
                                   client_registration_info=dict(client_id='abc',
                                                                 client_secret='foo'))
        assert len(authn.client.registration_response['redirect_uris']) == 1
        assert authn.client.registration_response['redirect_uris'][0] == "http://localhost/redirect_uri"
