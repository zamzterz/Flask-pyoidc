# Quickstart

To add authentication to one of your endpoints create the `OIDCAuthentication` object:

```python
from flask import Flask

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration

app = Flask(__name__)
app.config.update(
    OIDC_REDIRECT_URI = 'https://example.com/redirect_uri',
    SECRET_KEY = ...
)

# Static Client Registration
# If you have already registered a client with the provider, specify the client
# credentials directly:
client_metadata = ClientMetadata(
    client_id='client1',
    client_secret='secret1',
    post_logout_redirect_uris=['https://example.com/logout'])


provider_config = ProviderConfiguration(issuer='<issuer URL of provider>',
                                        client_metadata=client_metadata)

auth = OIDCAuthentication({'default': provider_config}, app)
```

You can also use a Flask application factory:
```python
config = ProviderConfiguration(...)
auth = OIDCAuthentication({'default': config})

def create_app():
    app = Flask(__name__)
    app.config.update(
        OIDC_REDIRECT_URI = 'https://example.com/redirect_uri',
        SECRET_KEY = ...
    )
    auth.init_app(app)
    return app
```

## OpenID Connect

To add user authentication via an OpenID Connect provider to your endpoints use the `oidc_auth` decorator:
```python
import flask
from flask import jsonify
from flask_pyoidc.user_session import UserSession

@app.route('/')
@auth.oidc_auth('default')
def index():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)
```

After a successful login, this extension will place three things in the user session (if they are received from the
provider):
* [ID Token](http://openid.net/specs/openid-connect-core-1_0.html#IDToken)
* [Access Token](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
* [Userinfo Response](http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)

In addition to this documentation, you may have a look on a 
[code example](https://github.com/zamzterz/Flask-pyoidc/tree/master/example).

## Token-Based Authorization

To add token-based authorization to your endpoints use the `token_auth`
decorator. It authorizes requests to your endpoint with Bearer tokens in
the `Authorization` header.

The token-based authorization is backed by
[token introspection](https://datatracker.ietf.org/doc/html/rfc7662)
so make sure the Identity Provider's introspection endpoint is configured.
```python
provider_metadata = ProviderMetadata(
    ...,
    introspection_endpoint='https://idp.example.com/introspect',
    ...)

@app.route('/api')
@auth.token_auth('default')
def api():
    current_token_identity = auth.current_token_identity
    ...

# Optionally, you can specify scopes required by your endpoint.
@app.route('/api')
@auth.token_auth('default',
                 scopes_required=['read', 'write'])
def api():
    current_token_identity = auth.current_token_identity
    ...
```
To obtain information about the token, use `auth.current_token_identity` inside
your view function. `current_token_identity` persists for current request only.

## Combined Authorization

If you want to apply both OIDC-based authentication and token-based
authorization on your endpoint, you can use `access_control` decorator.
Then the request will first be checked for a valid access token (in the `Authorization` header).
If there is no token in the request it will fall back to the OIDC-based authentication mechanism.

If there is a token in the request but it's invalid (e.g. expired, or missing required scopes) the request will
be rejected with a `403 Forbidden` response.


```python
# If you are using Static Provider Configuration, add introspection_endpoint
# in ProviderMetadata.
provider_metadata = ProviderMetadata(
    ...,
    introspection_endpoint='https://idp.example.com/introspect',
    ...)

@app.route('/api')
@auth.access_control('default')
def api():
    current_identity = None
    if auth.current_token_identity:
        current_identity = auth.current_token_identity
    else:
        current_identity = UserSession(flask.session)
    ...
```

## Using multiple providers

To allow users to login with multiple different providers, configure all of them in the `OIDCAuthentication`
constructor and specify which one to use by name for each endpoint:
```python
auth = OIDCAuthentication({'provider1': ProviderConfiguration(...), 'provider2': ProviderConfiguration(...)}, app)

@app.route('/login1')
@auth.oidc_auth('provider1')
def login1():
    ...

@app.route('/login2')
@auth.oidc_auth('provider2')
def login2():
    ...
```

## User logout

To support user logout, use the `oidc_logout` decorator:
```python
@app.route('/logout')
@auth.oidc_logout
def logout():
    return "You've been successfully logged out!"
```

If the logout view is mounted under a custom endpoint (other than the default, which is 
[the name of the view function](https://flask.palletsprojects.com/en/2.0.x/api/#flask.Flask.route)), or if using Blueprints, you
must specify the full URL in the Flask-pyoidc configuration using `post_logout_redirect_uris`:
```python
ClientMetadata(..., post_logout_redirect_uris=['https://example.com/post_logout']) # if using static client registration
ClientRegistrationInfo(..., post_logout_redirect_uris=['https://example.com/post_logout']) # if using dynamic client registration 
```

This extension also supports [RP-Initiated Logout](http://openid.net/specs/openid-connect-session-1_0.html#RPLogout),
if the provider allows it. Make sure the `end_session_endpoint` is defined in the provider metadata to enable notifying
the provider when the user logs out. 

## Refreshing the user access token

If the provider returns a refresh token, this extension can use it to automatically refresh the access token when it
has expired. Please see the helper method `OIDCAuthentication.valid_access_token()`.

## Specify the error view

If an OAuth error response is received, either in the authentication or token response, it will be passed to the
"error view", specified using the `error_view` decorator:

```python
from flask import jsonify

@auth.error_view
def error(error=None, error_description=None):
 return jsonify({'error': error, 'message': error_description})
```

The function specified as the error view MUST accept two parameters, `error` and `error_description`, which corresponds
to the [OIDC error parameters](http://openid.net/specs/openid-connect-core-1_0.html#AuthError), and return the content
that should be displayed to the user.

If no error view is specified, a generic error message will be displayed to the user.

## Client Credentials Flow
The [Client Credentials](https://tools.ietf.org/html/rfc6749#section-4.4) grant type can be used to obtain an
access token for your service (outside the context of a user).

You can obtain such an access token by using the `client_credentials_grant` method:

```python
token_response = auth.clients['default'].client_credentials_grant()
access_token = token_response.get('access_token')

# Optionally, you can specify scopes for the access token.
auth.clients['default'].client_credentials_grant(
    scope=['read', 'write'])
# You can also specify extra keyword arguments to client credentials flow.
auth.clients['default'].client_credentials_grant(
    scope=['read', 'write'], audience=['client_id1', 'client_id2'])
```

## Token Revocation
If you would like to disable an access or refresh token, simply send a request to the `/revoke` endpoint.

> Note: Revoking a token that is invalid, expired, or already revoked returns a 200 OK status code to prevent any information leaks.

```python
auth.clients['default'].revoke_token(token='access_token',
                                     token_type_hint='access_token')
```
