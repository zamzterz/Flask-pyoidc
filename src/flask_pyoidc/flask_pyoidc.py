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
from typing import Optional
from urllib.parse import parse_qsl

import flask
import importlib_resources
from flask import current_app, g
from flask.helpers import url_for
from oic import rndstr
from oic.extension.message import TokenIntrospectionResponse
from oic.oic import AuthorizationRequest
from oic.oic.message import EndSessionRequest
from werkzeug.exceptions import Forbidden, Unauthorized
from werkzeug.local import LocalProxy
from werkzeug.routing import BuildError
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

    def __init__(self, provider_configurations, app=None,
                 redirect_uri_config=None):
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
        self._logout_views = []
        self._error_view = None
        # current_token_identity proxy to obtain user info whose token was
        # passed in the request. It is available until current request only and
        # is destroyed between the requests. The value is set by token_auth
        # decorator.
        self.current_token_identity = LocalProxy(lambda: getattr(
            g, 'current_token_identity', None))
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

    def _get_urls_for_logout_views(self):
        try:
            return [url_for(view.__name__, _external=True) for view in self._logout_views]
        except BuildError:
            logger.error('could not build url for logout view, it might be mounted under a custom endpoint')
            raise

    def _register_client(self, client):
        if not client._provider_configuration._client_registration_info.get('redirect_uris'):
            client._provider_configuration._client_registration_info[
                'redirect_uris'] = [self._redirect_uri_config.full_uri]
        post_logout_redirect_uris = client._provider_configuration._client_registration_info.get(
            'post_logout_redirect_uris')
        if not post_logout_redirect_uris:
            client._provider_configuration._client_registration_info[
                'post_logout_redirect_uris'] = self._get_urls_for_logout_views()
        logger.debug(
            f'''registering with post_logout_redirect_uris = {
                client._provider_configuration._client_registration_info[
                    'post_logout_redirect_uris']}''')
        client.register()

    def _authenticate(self, client, interactive=True):
        if not client.is_registered():
            self._register_client(client)

        flask.session['destination'] = flask.request.full_path

        # Use silent authentication for session refresh
        # This will not show login prompt to the user
        extra_auth_params = {}
        if not interactive:
            extra_auth_params['prompt'] = 'none'

        auth_req = client.authentication_request(state=rndstr(),
                                                 nonce=rndstr(),
                                                 extra_auth_params=extra_auth_params)
        flask.session['auth_request'] = auth_req.to_json()
        login_url = client.login_url(auth_req)

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

        if flask.session.pop('fragment_encoded_response', False):
            return (importlib_resources.files('flask_pyoidc') / 'parse_fragment.html').read_text(encoding='utf-8')

        if 'auth_request' not in flask.session:
            return self._handle_error_response({'error': 'unsolicited_response', 'error_description': 'No authentication request stored.'})
        auth_request = AuthorizationRequest().from_json(flask.session.pop('auth_request'))

        is_processing_fragment_encoded_response = flask.request.method == 'POST'
        if is_processing_fragment_encoded_response:
            auth_resp = flask.request.form
        else:
            auth_resp = flask.request.args

        client = self.clients[session.current_provider]

        authn_resp = client.parse_authentication_response(auth_resp)
        logger.debug('received authentication response: %s', authn_resp.to_json())

        try:
            extra_token_args = {}
            if 'OIDC_CLOCK_SKEW' in current_app.config:
                extra_token_args['skew'] = current_app.config['OIDC_CLOCK_SKEW']
            result = AuthResponseHandler(client).process_auth_response(authn_resp, auth_request, extra_token_args)
        except AuthResponseErrorResponseError as ex:
            return self._handle_error_response(ex.error_response, is_processing_fragment_encoded_response)
        except AuthResponseProcessError as ex:
            return self._handle_error_response({'error': 'unexpected_error', 'error_description': str(ex)},
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

    def oidc_auth(self, provider_name: str):

        if provider_name not in self._provider_configurations:
            raise ValueError(
                f"Provider name '{provider_name}' not in configured providers: {self._provider_configurations.keys()}."
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

    def _logout(self, post_logout_redirect_uri):
        logger.debug('user logout')
        try:
            session = UserSession(flask.session)
        except UninitialisedSession:
            logger.info('user was already logged out, doing nothing')
            return None

        id_token_jwt = session.id_token_jwt
        client = self.clients[session.current_provider]
        session.clear()

        if client.provider_end_session_endpoint:
            flask.session['end_session_state'] = rndstr()

            end_session_request = EndSessionRequest(id_token_hint=id_token_jwt,
                                                    post_logout_redirect_uri=post_logout_redirect_uri,
                                                    state=flask.session['end_session_state'])

            logger.debug('send endsession request: %s', end_session_request.to_json())

            return redirect(end_session_request.request(client.provider_end_session_endpoint), 303)
        return None

    def oidc_logout(self, view_func):
        self._logout_views.append(view_func)

        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            if 'state' in flask.request.args:
                # returning redirect from provider
                if flask.request.args['state'] != flask.session.pop('end_session_state', None):
                    logger.error("Got unexpected state '%s' after logout redirect.", flask.request.args['state'])
                return view_func(*args, **kwargs)

            post_logout_redirect_uri = flask.request.url
            redirect_to_provider = self._logout(post_logout_redirect_uri)
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

    @staticmethod
    def _check_authorization_header(request) -> bool:
        """Look for authorization in request header.

        Parameters
        ----------
        request : flask.Request
            flask request object.

        Returns
        -------
        bool
            True if the request header contains authorization else False.
        """
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
            return True
        return False

    @staticmethod
    def _parse_access_token(request) -> str:
        """Parse access token from the authorization request header.

        Parameters
        ----------
        request : flask.Request
            flask request object.

        Returns
        -------
        accept_token : str
            access token from the request header.
        """
        _, access_token = request.headers['Authorization'].split(maxsplit=1)
        return access_token

    def introspect_token(self, request, client, scopes: list = None) ->\
            Optional[TokenIntrospectionResponse]:
        """RFC 7662: Token Introspection
        The Token Introspection extension defines a mechanism for resource
        servers to obtain information about access tokens. With this spec,
        resource servers can check the validity of access tokens, and find out
        other information such as which user and which scopes are associated
        with the token.

        Parameters
        ----------
        request : flask.Request
            flask request object.
        client : flask_pyoidc.pyoidc_facade.PyoidcFacade
            PyoidcFacade object contains metadata of the provider and client.
        scopes : list, optional
            Specify scopes required by your endpoint.

        Returns
        -------
        result: TokenIntrospectionResponse or None
            If access_token is valid or None if invalid.
        """
        received_access_token = self._parse_access_token(request)
        # send token introspection request
        result = client._token_introspection_request(
            access_token=received_access_token)
        logger.debug(result)
        # Check if access_token is valid, active can be True or False
        if not result.get('active'):
            return None
        # Check if client_id is in audience claim
        if client._client.client_id not in result['aud']:
            # log the exception if client_id is not in audience and returns
            # False, you can configure audience with Identity Provider
            logger.info('Token is valid but required audience is missing.')
            return None
        # Check if the scopes associated with the access_token are the ones
        # required by the endpoint and not something else which is not
        # permitted.
        if scopes and not set(scopes).issubset(set(result['scope'])):
            logger.info('Token is valid but does not have required scopes.')
            return None
        return result

    def token_auth(self, provider_name, scopes_required: list = None):
        """Token based authorization.

        Parameters
        ----------
        provider_name : str
            Name of the provider registered with OIDCAuthorization.
        scopes_required : list, optional
            List of valid scopes associated with the endpoint.

        Raises
        ------
        Unauthorized
            flask.abort(401) if authorization field is missing.
        Forbidden
            flask.abort(403) if access token is invalid.

        Examples
        --------
        ::

            auth = OIDCAuthentication({'default': provider_config})
            @app.route('/')
            @auth.token_auth(provider_name='default')
            def index():
                ...

        You can also specify scopes required by the endpoint.

        ::

            @auth.token_auth(provider_name='default',
                             scopes_required=['read', 'write'])
        """
        def token_decorator(view_func):

            @functools.wraps(view_func)
            def wrapper(*args, **kwargs):

                client = self.clients[provider_name]
                # Check for authorization field in the request header.
                if not self._check_authorization_header(flask.request):
                    logger.info('Request header has no authorization field')
                    # Abort the request if authorization field is missing.
                    flask.abort(401)
                token_introspection_result = self.introspect_token(
                    request=flask.request, client=client,
                    scopes=scopes_required)
                if token_introspection_result:
                    logger.info('Request has valid access token.')
                    # Store token introspection info within the application
                    # context.
                    g.current_token_identity = token_introspection_result.to_dict()
                    return view_func(*args, **kwargs)
                # Forbid access if the access token is invalid.
                flask.abort(403)

            return wrapper

        return token_decorator

    def access_control(self, provider_name: str,
                       scopes_required: list = None):
        """This decorator serves dual purpose that is it can do both token
        based authorization and oidc based authentication. If your API needs
        to be accessible by either modes, use this decorator otherwise use
        either oidc_auth or token_auth.

        Parameters
        ----------
        provider_name : str
            Name of the provider registered with OIDCAuthorization.
        scopes_required : list, optional
            List of valid scopes associated with the endpoint.

        Raises
        ------
        Forbidden
            If accesss_token is invalid.

        Examples
        --------
        ::

            auth = OIDCAuthentication({'default': provider_config})
            @app.route('/')
            @auth.access_control(provider_name='default')
            def index():
                ...

        You can also specify scopes required by the endpoint:

        ::

            @auth.access_control(provider_name='default',
                                 scopes_required=['read', 'write'])
        """
        def hybrid_decorator(view_func):

            fallback_to_oidc = self.oidc_auth(provider_name)(view_func)

            @functools.wraps(view_func)
            def wrapper(*args, **kwargs):

                try:
                    # If the request header contains authorization, token_auth
                    # verifies the access_token otherwise an exception occurs
                    # and the request falls back to oidc_auth.
                    return self.token_auth(provider_name, scopes_required)(
                        view_func)(*args, **kwargs)
                # token_auth will raise the HTTPException if either
                # authorization field is missing from the request header or
                # token is invalid. If the authorization field is missing,
                # fallback to oidc.
                except Unauthorized:
                    return fallback_to_oidc(*args, **kwargs)
                # If token is present, but it's invalid, do not fall back to
                # oidc_auth. Instead, abort the request.
                except Forbidden:
                    flask.abort(403)

            return wrapper

        return hybrid_decorator
