import functools

import logging

import flask
from flask.helpers import url_for
from oic import rndstr
from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest, AuthorizationResponse, EndSessionRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from werkzeug.utils import redirect
import time

logger = logging.getLogger(__name__)


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

        self.logout_view = None
        self._error_view = None

    def _authenticate(self, interactive=True):
        if 'client_id' not in self.client_registration_info:
            logger.debug('performing dynamic client registration')
            # do dynamic registration
            if self.logout_view:
                # handle support for logout
                with self.app.app_context():
                    post_logout_redirect_uri = url_for(self.logout_view.__name__, _external=True)
                    logger.debug('built post_logout_redirect_uri=%s', post_logout_redirect_uri)
                    self.client_registration_info['post_logout_redirect_uris'] = [post_logout_redirect_uri]

            registration_response = self.client.register(self.client.provider_info['registration_endpoint'],
                                                         **self.client_registration_info)
            logger.debug('client registration response: %s', registration_response.to_json())

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
        # Use silent authentication for session refresh (will not show login prompt to the user)
        if not interactive:
            args['prompt'] = 'none'

        args.update(self.extra_request_args)
        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        logger.debug('sending authentication request: %s', auth_req.to_json())

        login_url = auth_req.request(self.client.authorization_endpoint)
        return redirect(login_url)

    def _handle_authentication_response(self):
        # parse authentication response
        query_string = flask.request.query_string.decode('utf-8')
        authn_resp = self.client.parse_response(AuthorizationResponse, info=query_string,
                                                sformat='urlencoded')
        logger.debug('received authentication response: %s', authn_resp.to_json())

        if authn_resp['state'] != flask.session.pop('state'):
            raise ValueError('The \'state\' parameter does not match.')

        if 'error' in authn_resp:
            return self._handle_error_response(authn_resp)

        # do token request
        args = {
            'code': authn_resp['code'],
            'redirect_uri': self.client.registration_response['redirect_uris'][0],
        }

        logger.debug('making token request')
        token_resp = self.client.do_access_token_request(state=authn_resp['state'],
                                                         request_args=args,
                                                         authn_method=self.client.registration_response.get(
                                                             'token_endpoint_auth_method', 'client_secret_basic'))
        logger.debug('received token response: %s', token_resp.to_json())

        if 'error' in token_resp:
            return self._handle_error_response(token_resp)

        flask.session['access_token'] = token_resp['access_token']

        id_token = None
        if 'id_token' in token_resp:
            id_token = token_resp['id_token']
            logger.debug('received id token: %s', id_token.to_json())
            if id_token['nonce'] != flask.session.pop('nonce'):
                raise ValueError('The \'nonce\' parameter does not match.')
            flask.session['id_token'] = id_token.to_dict()
            flask.session['id_token_jwt'] = id_token.jwt

        # do userinfo request
        userinfo = self._do_userinfo_request(authn_resp['state'], self.userinfo_endpoint_method)
        if id_token and userinfo and userinfo['sub'] != id_token['sub']:
            raise ValueError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

        # store the current user session
        if userinfo:
            flask.session['userinfo'] = userinfo.to_dict()

        flask.session['last_authenticated'] = time.time()
        destination = flask.session.pop('destination')
        return redirect(destination)

    def _do_userinfo_request(self, state, userinfo_endpoint_method):
        if userinfo_endpoint_method is None:
            return None

        logger.debug('making userinfo request')
        userinfo_response = self.client.do_user_info_request(method=userinfo_endpoint_method, state=state)
        logger.debug('received userinfo response: %s', userinfo_response.to_json())
        return userinfo_response

    def _handle_error_response(self, error_response):
        if self._error_view:
            error = {k: error_response[k] for k in ['error', 'error_description'] if k in error_response}
            return self._error_view(**error)

        return 'Something went wrong with the authentication, please try to login again.'

    def oidc_auth(self, view_func):
        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            if flask.session.get('id_token_jwt'):
                if ('session_refresh_interval' in self.client_registration_info) and flask.session.get('last_authenticated'):
		    if flask.session.get('last_authenticated') + self.client_registration_info['session_refresh_interval'] < time.time():
                        logger.debug('user session needs refresh')
                        return self._authenticate(interactive=False)
                logger.debug('user is already authenticated')
                return view_func(*args, **kwargs)
            else:
                logger.debug('user not authenticated, start flow')
                return self._authenticate()

        return wrapper

    def _logout(self):
        logger.debug('user logout')
        id_token_jwt = flask.session['id_token_jwt']
        flask.session.clear()

        if 'end_session_endpoint' in self.client.provider_info:
            flask.session['end_session_state'] = rndstr()
            end_session_request = EndSessionRequest(
                id_token_hint=id_token_jwt,
                post_logout_redirect_uri=self.client_registration_info['post_logout_redirect_uris'][0],
                state=flask.session['end_session_state'])
            logger.debug('send endsession request: %s', end_session_request.to_json())
            return redirect(end_session_request.request(self.client.provider_info['end_session_endpoint']), 303)

        return None

    def oidc_logout(self, view_func):
        self.logout_view = view_func

        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            if 'state' in flask.request.args:
                # returning redirect from provider
                assert flask.request.args['state'] == flask.session.pop('end_session_state')
                return view_func(*args, **kwargs)

            redirect_to_provider = self._logout()
            if redirect_to_provider:
                return redirect_to_provider

            return view_func(*args, **kwargs)

        return wrapper

    def error_view(self, view_func):
        self._error_view = view_func
        return view_func
