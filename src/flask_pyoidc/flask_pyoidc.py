#   Copyright 2018 Samuel Gulliksson
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


import functools
import json
import logging
import time
from urllib.parse import parse_qsl

import flask
import importlib_resources
from flask import current_app
from flask.helpers import url_for
from oic import rndstr
from oic.oic.message import EndSessionRequest
from werkzeug.utils import redirect

from .auth_response_handler import AuthResponseProcessError, AuthResponseHandler, AuthResponseErrorResponseError
from .pyoidc_facade import PyoidcFacade
from .redirect_uri_config import RedirectUriConfig
from .user_session import UninitialisedSession, UserSession

logger = logging.getLogger(__name__)


class OIDCAuthentication:
    """
    OIDCAuthentication object for Flask extension.
    """

    def __init__(self, provider_configurations, app=None, redirect_uri_config = None):
        """
        Args:
            provider_configurations (Mapping[str, ProviderConfiguration]):
                provider configurations by name
            app (flask.app.Flask): optional Flask app
            redirect_uri_config (RedirectUriConfig): optional redirect URI config to use instead of
                'OIDC_REDIRECT_URI' config parameter.
        """
        self._provider_configurations = provider_configurations

        self.clients = None
        self._logout_view = None
        self._error_view = None
        self._redirect_uri_config = redirect_uri_config

        if app:
            self.init_app(app)

    def init_app(self, app):
        if not self._redirect_uri_config:
            self._redirect_uri_config = RedirectUriConfig.from_config(app.config)

        # setup redirect_uri as a flask route
        app.add_url_rule('/' + self._redirect_uri_config.endpoint,
                         self._redirect_uri_config.endpoint,
                         self._handle_authentication_response,
                         methods=['GET', 'POST'])

        # dynamically add the Flask redirect uri to the client info
        self.clients = {
            name: PyoidcFacade(configuration, self._redirect_uri_config.full_uri)
            for (name, configuration) in self._provider_configurations.items()
        }

    def _get_post_logout_redirect_uri(self, client):
        if client.post_logout_redirect_uris:
            return client.post_logout_redirect_uris[0]
        return self._get_url_for_logout_view()

    def _get_url_for_logout_view(self):
        return url_for(self._logout_view.__name__, _external=True) if self._logout_view else None

    def _register_client(self, client):
        def default_post_logout_redirect_uris():
            url_for_logout_view = self._get_url_for_logout_view()
            if url_for_logout_view:
                return [url_for_logout_view]
            return []

        client_registration_args = {}
        post_logout_redirect_uris = client._provider_configuration._client_registration_info.get(
            'post_logout_redirect_uris',
            default_post_logout_redirect_uris())
        if post_logout_redirect_uris:
            logger.debug('registering with post_logout_redirect_uris=%s', post_logout_redirect_uris)
            client_registration_args['post_logout_redirect_uris'] = post_logout_redirect_uris
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

        auth_params = dict(parse_qsl(login_url.split('?')[1]))
        flask.session['fragment_encoded_response'] = AuthResponseHandler.expect_fragment_encoded_response(auth_params)
        return redirect(login_url)

    def _handle_authentication_response(self):
        has_error = flask.request.args.get('error', False, lambda x: bool(int(x)))
        if has_error:
            if 'error' in flask.session:
                return self._show_error_response(flask.session.pop('error'))
            return 'Something went wrong.'

        try:
            session = UserSession(flask.session)
        except UninitialisedSession:
            return self._handle_error_response({'error': 'unsolicited_response', 'error_description': 'No initialised user session.'})

        if 'state' not in flask.session:
            return self._handle_error_response({'error': 'unsolicited_response', 'error_description': "No 'state' stored."})
        elif 'nonce' not in flask.session:
            return self._handle_error_response({'error': 'unsolicited_response', 'error_description': "No 'nonce' stored."})

        if flask.session.pop('fragment_encoded_response', False):
            return importlib_resources.read_binary('flask_pyoidc', 'parse_fragment.html').decode('utf-8')

        is_processing_fragment_encoded_response = flask.request.method == 'POST'

        if is_processing_fragment_encoded_response:
            auth_resp = flask.request.form
        else:
            auth_resp = flask.request.args

        client = self.clients[session.current_provider]

        authn_resp = client.parse_authentication_response(auth_resp)
        logger.debug('received authentication response: %s', authn_resp.to_json())

        try:
            result = AuthResponseHandler(client).process_auth_response(authn_resp,
                                                                       flask.session.pop('state'),
                                                                       flask.session.pop('nonce'))
        except AuthResponseErrorResponseError as e:
            return self._handle_error_response(e.error_response, is_processing_fragment_encoded_response)
        except AuthResponseProcessError as e:
            return self._handle_error_response({'error': 'unexpected_error', 'error_description': str(e)},
                                               is_processing_fragment_encoded_response)

        if current_app.config.get('OIDC_SESSION_PERMANENT', True):
            flask.session.permanent = True

        UserSession(flask.session).update(access_token=result.access_token,
                                          expires_in=result.expires_in,
                                          id_token=result.id_token_claims,
                                          id_token_jwt=result.id_token_jwt,
                                          userinfo=result.userinfo_claims,
                                          refresh_token=result.refresh_token)

        destination = flask.session.pop('destination')
        if is_processing_fragment_encoded_response:
            # if the POST request was from the JS page handling fragment encoded responses we need to return
            # the destination URL as the response body
            return destination

        return redirect(destination)

    def _handle_error_response(self, error_response, should_redirect=False):
        if should_redirect:
            # if the current request was from the JS page handling fragment encoded responses we need to return
            # a URL for the error page to redirect to
            flask.session['error'] = error_response
            return '/' + self._redirect_uri_config.endpoint + '?error=1'
        return self._show_error_response(error_response)

    def _show_error_response(self, error_response):
        logger.error(json.dumps(error_response))
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
        try:
            session = UserSession(flask.session)
        except UninitialisedSession as e:
            logger.info('user was already logged out, doing nothing')
            return None

        id_token_jwt = session.id_token_jwt
        client = self.clients[session.current_provider]
        session.clear()

        if client.provider_end_session_endpoint:
            flask.session['end_session_state'] = rndstr()

            end_session_request = EndSessionRequest(id_token_hint=id_token_jwt,
                                                    post_logout_redirect_uri=self._get_post_logout_redirect_uri(client),
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

    def valid_access_token(self, force_refresh=False):
        """
        Returns a valid access token.

        1. If the current access token in the user session is valid, return that.
        2. If the current access token has expired and there is a refresh token in the user session,
           make a refresh token request and return the new access token.
        3. If the token refresh fails, either due to missing refresh token or token error response, return None.

        Args:
            force_refresh (bool): whether to perform the refresh token request even if the current access token is valid
        Returns:
            Option[str]: valid access token
        """
        try:
            session = UserSession(flask.session)
        except UninitialisedSession:
            logger.debug('user does not have an active session')
            return None

        has_expired = session.access_token_expires_at < time.time() if session.access_token_expires_at else False
        if not has_expired and not force_refresh:
            logger.debug("access token doesn't need to be refreshed")
            return session.access_token

        if not session.refresh_token:
            logger.info('no refresh token exists in the session')
            return None

        client = self.clients[session.current_provider]
        response = client.refresh_token(session.refresh_token)
        if 'error' in response:
            logger.info('failed to refresh access token: ' + json.dumps(response.to_dict()))
            return None

        access_token = response.get('access_token')
        session.update(access_token=access_token,
                       expires_in=response.get('expires_in'),
                       id_token=response['id_token'].to_dict() if 'id_token' in response else None,
                       id_token_jwt=response.get('id_token_jwt'),
                       refresh_token=response.get('refresh_token'))
        return access_token
