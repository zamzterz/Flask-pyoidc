"""
   Copyright 2018 Samuel Gulliksson

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import time

import flask
import functools
import logging
from flask import current_app
from flask.helpers import url_for
from oic import rndstr
from oic.oic.message import EndSessionRequest
from werkzeug.utils import redirect

from .pyoidc_facade import PyoidcFacade
from .user_session import UserSession

logger = logging.getLogger(__name__)


class OIDCAuthentication(object):
    """
    OIDCAuthentication object for Flask extension.
    """

    REDIRECT_URI_ENDPOINT = 'redirect_uri'

    def __init__(self, provider_configurations, app=None):
        """
        Args:
            provider_configurations (Mapping[str, flask_pyoidc.provider_configuration.ProviderConfiguration]):
                provider configurations by name
            app (flask.app.Flask): optional Flask app
        """
        self._provider_configurations = provider_configurations

        self.clients = None
        self._logout_view = None
        self._error_view = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        # setup redirect_uri as a flask route
        app.add_url_rule('/redirect_uri', self.REDIRECT_URI_ENDPOINT, self._handle_authentication_response)

        # dynamically add the Flask redirect uri to the client info
        with app.app_context():
            self.clients = {
                name: PyoidcFacade(configuration, url_for(self.REDIRECT_URI_ENDPOINT))
                for (name, configuration) in self._provider_configurations.items()
            }

    def _get_post_logout_redirect_uri(self):
        if self._logout_view:
            return url_for(self._logout_view.__name__, _external=True)
        return None

    def _register_client(self, client):
        client_registration_args = {}
        post_logout_redirect_uri = self._get_post_logout_redirect_uri()
        if post_logout_redirect_uri:
            logger.debug('registering with post_logout_redirect_uri=%s', post_logout_redirect_uri)
            client_registration_args['post_logout_redirect_uris'] = [post_logout_redirect_uri]
        client.register(client_registration_args)

    def _authenticate(self, client, interactive=True):
        if not client.is_registered():
            self._register_client(client)

        flask.session['destination'] = flask.request.url
        flask.session['state'] = rndstr()
        flask.session['nonce'] = rndstr()

        # Use silent authentication for session refresh
        # This will not show login prompt to the user
        extra_auth_params = {}
        if not interactive:
            extra_auth_params['prompt'] = 'none'

        login_url = client.authentication_request(flask.session['state'],
                                                  flask.session['nonce'],
                                                  extra_auth_params)
        return redirect(login_url)

    def _handle_authentication_response(self):
        client = self.clients[UserSession(flask.session).current_provider]

        # parse authentication response
        query_string = flask.request.query_string.decode('utf-8')
        authn_resp = client.parse_authentication_response(query_string)
        logger.debug('received authentication response: %s', authn_resp.to_json())

        if authn_resp['state'] != flask.session.pop('state'):
            raise ValueError('The \'state\' parameter does not match.')

        if 'error' in authn_resp:
            return self._handle_error_response(authn_resp)

        token_resp = client.token_request(authn_resp['code'])

        if 'error' in token_resp:
            return self._handle_error_response(token_resp)

        access_token = token_resp['access_token']

        id_token_claims = None
        if 'id_token' in token_resp:
            id_token = token_resp['id_token']
            logger.debug('received id token: %s', id_token.to_json())

            if id_token['nonce'] != flask.session.pop('nonce'):
                raise ValueError('The \'nonce\' parameter does not match.')

            id_token_claims = id_token.to_dict()

        # do userinfo request
        userinfo = client.userinfo_request(access_token)
        userinfo_claims = None
        if userinfo:
            userinfo_claims = userinfo.to_dict()

        if id_token_claims and userinfo_claims and userinfo_claims['sub'] != id_token_claims['sub']:
            raise ValueError('The \'sub\' of userinfo does not match \'sub\' of ID Token.')

        if current_app.config.get('OIDC_SESSION_PERMANENT', True):
            flask.session.permanent = True

        UserSession(flask.session).update(access_token,
                                          id_token_claims,
                                          token_resp.get('id_token_jwt'),
                                          userinfo_claims)

        destination = flask.session.pop('destination')
        return redirect(destination)

    def _handle_error_response(self, error_response):
        if self._error_view:
            error = {k: error_response[k] for k in ['error', 'error_description'] if k in error_response}
            return self._error_view(**error)

        return 'Something went wrong with the authentication, please try to login again.'

    def oidc_auth(self, provider_name):
        if provider_name not in self._provider_configurations:
            raise ValueError(
                "Provider name '{}' not in configured providers: {}.".format(provider_name,
                                                                             self._provider_configurations.keys())
            )

        def oidc_decorator(view_func):
            @functools.wraps(view_func)
            def wrapper(*args, **kwargs):
                session = UserSession(flask.session, provider_name)
                client = self.clients[session.current_provider]

                if session.should_refresh(client.session_refresh_interval_seconds):
                    logger.debug('user auth will be refreshed "silently"')
                    return self._authenticate(client, interactive=False)
                elif session.is_authenticated():
                    logger.debug('user is already authenticated')
                    return view_func(*args, **kwargs)
                else:
                    logger.debug('user not authenticated, start flow')
                    return self._authenticate(client)

            return wrapper

        return oidc_decorator

    def _logout(self):
        logger.debug('user logout')
        session = UserSession(flask.session)
        id_token_jwt = session.id_token_jwt
        client = self.clients[session.current_provider]
        session.clear()

        if client.provider_end_session_endpoint:
            flask.session['end_session_state'] = rndstr()

            end_session_request = EndSessionRequest(id_token_hint=id_token_jwt,
                                                    post_logout_redirect_uri=self._get_post_logout_redirect_uri(),
                                                    state=flask.session['end_session_state'])

            logger.debug('send endsession request: %s', end_session_request.to_json())

            return redirect(end_session_request.request(client.provider_end_session_endpoint), 303)
        return None

    def oidc_logout(self, view_func):
        self._logout_view = view_func

        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            if 'state' in flask.request.args:
                # returning redirect from provider
                if flask.request.args['state'] != flask.session.pop('end_session_state'):
                    logger.error("Got unexpected state '%s' after logout redirect.", flask.request.args['state'])
                return view_func(*args, **kwargs)

            redirect_to_provider = self._logout()
            if redirect_to_provider:
                return redirect_to_provider

            return view_func(*args, **kwargs)

        return wrapper

    def error_view(self, view_func):
        self._error_view = view_func
        return view_func
