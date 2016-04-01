import flask
import functools

import time
from flask.helpers import url_for
from oic import rndstr
from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest, \
    AuthorizationResponse, IdToken, OpenIDSchema
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from werkzeug.utils import redirect


class OIDCAuthentication(object):
    def __init__(self, flask_app, client_registration_info=None, issuer=None,
                 provider_configuration_info=None, userinfo_endpoint_method='POST',
                 extra_request_args=None):
        self.app = flask_app
        self.userinfo_endpoint_method = userinfo_endpoint_method
        self.extra_request_args = extra_request_args or {}

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


    def _authenticate(self):
        flask.session['destination'] = flask.request.url
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

        args.update(self.extra_request_args)
        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(self.client.authorization_endpoint)
        return redirect(login_url)

    def _handle_authentication_response(self):
        # parse authentication response
        query_string = flask.request.query_string.decode('utf-8')
        authn_resp = self.client.parse_response(AuthorizationResponse, info=query_string,
                                                sformat='urlencoded')

        if authn_resp['state'] != flask.session.pop('state'):
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
        if id_token['nonce'] != flask.session.pop('nonce'):
            raise ValueError('The \'nonce\' parameter does not match.')
        access_token = token_resp['access_token']

        # do userinfo request
        userinfo = self._do_userinfo_request(authn_resp['state'], self.userinfo_endpoint_method)
        if userinfo['sub'] != id_token['sub']:
            raise ValueError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

        # store the current user session
        flask.session['id_token'] = id_token.to_dict()
        flask.session['access_token'] = access_token
        if userinfo:
            flask.session['userinfo'] = userinfo.to_dict()

        destination = flask.session.pop('destination')
        return redirect(destination)

    def _do_userinfo_request(self, state, userinfo_endpoint_method):
        if userinfo_endpoint_method is None:
            return None

        return self.client.do_user_info_request(method=userinfo_endpoint_method, state=state)

    def _reauthentication_necessary(self, id_token, now=None):
        if id_token is None:
            return True

        id_token_exp = id_token['exp']
        now_ts = now or time.time()
        if now_ts > id_token_exp:
            return True

        return False

    def oidc_auth(self, view_func):
        @functools.wraps(view_func)
        def wrapper():
            if not self._reauthentication_necessary(flask.session.get('id_token')):
                # fetch user session and make accessible for view function
                self._unpack_user_session()
                return view_func()

            return self._authenticate()

        return wrapper

    def _unpack_user_session(self):
        flask.g.id_token = IdToken().from_dict(flask.session.get('id_token'))
        flask.g.access_token = flask.session.get('access_token')
        userinfo_dict = flask.session.get('userinfo')
        if userinfo_dict:
            flask.g.userinfo = OpenIDSchema().from_dict(userinfo_dict)