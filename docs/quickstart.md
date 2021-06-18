# Quickstart

To add authentication to one of your endpoints use the `oidc_auth` decorator:
```python
import flask
from flask import Flask, jsonify

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
app.config.update(
    OIDC_REDIRECT_URI = 'https://example.com/redirect_uri',
    SECRET_KEY = ...
)
config = ProviderConfiguration(...)
auth = OIDCAuthentication({'default': config}, app)

@app.route('/login')
@auth.oidc_auth('default')
def index():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)
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

After a successful login, this extension will place three things in the user session (if they are received from the
provider):
* [ID Token](http://openid.net/specs/openid-connect-core-1_0.html#IDToken)
* [Access Token](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
* [Userinfo Response](http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)

In addition to this documentation, you may have a look on a 
[code example](https://github.com/zamzterz/Flask-pyoidc/tree/master/example).

## Using multiple providers

To allow users to login with multiple different providers, configure all of them in the `OIDCAuthentication`
constructor and specify which one to use by name for each endpoint:
```python
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration

app = Flask(__name__)
app.config.update(
    OIDC_REDIRECT_URI = 'https://example.com/redirect_uri',
    SECRET_KEY = ...
)
auth = OIDCAuthentication({'provider1': ProviderConfiguration(...), 'provider2': ProviderConfiguration(...)}, app)

@app.route('/login1')
@auth.oidc_auth('provider1')
def login1():
    pass

@app.route('/login2')
@auth.oidc_auth('provider2')
def login2():
    pass
```

## User logout

To support user logout, use the `oidc_logout` decorator:
```python
@app.route('/logout')
@auth.oidc_logout
def logout():
    return 'You\'ve been successfully logged out!'
```

If the logout view is mounted under a custom endpoint (other than the default, which is 
[the name of the view function](http://flask.pocoo.org/docs/1.0/api/#flask.Flask.route)), or if using Blueprints, you
must specify the full URL in the Flask-pyoidc configuration using `post_logout_redirect_uris`:
```python
ClientMetadata(..., post_logout_redirect_uris=['https://example.com/post_logout']) # if using static client registration
ClientRegistrationInfo(..., post_logout_redirect_uris=['https://example.com/post_logout']) # if using dynamic client registration 
```

This extension also supports [RP-Initiated Logout](http://openid.net/specs/openid-connect-session-1_0.html#RPLogout),
if the provider allows it. Make sure the `end_session_endpoint` is defined in the provider metadata to enable notifying
the provider when the user logs out. 

## Refreshing the access token

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
