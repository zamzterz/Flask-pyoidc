import functools

import flask
from flask.helpers import url_for
from oic import rndstr
from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest, \
    AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from werkzeug.utils import redirect


class OIDCAuthentication(object):
    def __init__(self, flask_app, client_registration_info=None, issuer=None,
                 provider_configuration_info=None):
        self.app = flask_app

        self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
        if not issuer and not provider_configuration_info:
            raise ValueError(
                    'Either \'issuer\' (for dynamic discovery) or \'provider_configuration_info\' (for static configuration must be specified.')
        if issuer and not provider_configuration_info:
            self.client.provider_config(issuer)
        else:
            self.client.handle_provider_config(
                    ProviderConfigurationResponse(**provider_configuration_info),
                    provider_configuration_info['issuer'])

        self.client_registration_info = client_registration_info or {}

        # setup redirect_uri
        self.app.add_url_rule('/redirect_uri', 'redirect_uri',
                              self._handle_authentication_response)
        with self.app.app_context():
            self.client_registration_info['redirect_uris'] = url_for('redirect_uri')

        if client_registration_info and 'client_id' in client_registration_info:
            # static client info provided
            self.client.store_registration_info(RegistrationRequest(**client_registration_info))
        else:
            # do dynamic registration
            self.client.register(self.client.provider_info['registration_endpoint'],
                                 **self.client_registration_info)

        self.callback = None

    def _authenticate(self):
        if flask.g.get('userinfo', None):
            return self.callback()

        flask.session['state'] = rndstr()
        flask.session['nonce'] = rndstr()
        args = {
            'client_id': self.client.client_id,
            'response_type': 'code',
            'scope': ['openid'],
            'redirect_uri': self.client.registration_response['redirect_uris'][0],
            'state': flask.session['state'],
            'nonce': flask.session['nonce'],
        }

        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(self.client.authorization_endpoint)
        return redirect(login_url)

    def _handle_authentication_response(self):
        # parse authentication response
        query_string = flask.request.query_string.decode('utf-8')
        authn_resp = self.client.parse_response(AuthorizationResponse, info=query_string,
                                                sformat='urlencoded')

        if authn_resp['state'] != flask.session['state']:
            raise ValueError('The \'state\' parameter does not match.')

        # do token request
        args = {
            'code': authn_resp['code'],
            'redirect_uri': self.client.registration_response['redirect_uris'][0],
            'client_id': self.client.client_id,
            'client_secret': self.client.client_secret
        }
        token_resp = self.client.do_access_token_request(scope='openid', state=authn_resp['state'],
                                                         request_args=args,
                                                         authn_method='client_secret_basic')
        id_token = token_resp['id_token']
        if id_token['nonce'] != flask.session['nonce']:
            raise ValueError('The \'nonce\' parameter does not match.')
        access_token = token_resp['access_token']

        # do userinfo request
        userinfo = self.client.do_user_info_request(state=authn_resp['state'])
        if userinfo['sub'] != id_token['sub']:
            raise ValueError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

        # store the current user
        flask.g.id_token = id_token
        flask.g.access_token = access_token
        flask.g.userinfo = userinfo

        return self.callback()

    def oidc_auth(self, f):
        self.callback = f

        @functools.wraps(f)
        def wrapper():
            return self._authenticate()

        return wrapper
