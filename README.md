# Flask-pyoidc

[![PyPI](https://img.shields.io/pypi/v/flask-pyoidc.svg)](https://pypi.python.org/pypi/Flask-pyoidc)
[![codecov.io](https://codecov.io/github/zamzterz/Flask-pyoidc/coverage.svg?branch=master)](https://codecov.io/github/its-dirg/Flask-pyoidc?branch=master)
[![Build Status](https://travis-ci.org/zamzterz/Flask-pyoidc.svg?branch=master)](https://travis-ci.org/zamzterz/Flask-pyoidc)

This Flask extension provides simple OpenID Connect authentication, backed by [pyoidc](https://github.com/rohe/pyoidc).

["Authorization Code Flow"](http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth), as well as
["Implicit Flow"](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth) and 
["Hybrid Flow"](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth), is supported.

## Example

Have a look at the [example Flask app](example/app.py) for a full example of how to use this extension.

## Configuration

### Provider and client configuration

Both static and dynamic provider configuration discovery, as well as static
and dynamic client registration, is supported. The different modes of provider configuration can be combined with any
of the client registration modes.

#### Dynamic provider configuration

To use a provider which supports dynamic discovery it suffices to specify the issuer URL:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration

config = ProviderConfiguration(issuer='https://op.example.com', [client configuration])
```

#### Static provider configuration

To use a provider not supporting dynamic discovery, the static provider metadata can be specified:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata

provider_metadata = ProviderMetadata(issuer='https://op.example.com', 
                                     authorization_endpoint='https://op.example.com/auth',
                                     jwks_uri='https://op.example.com/jwks')
config = ProviderConfiguration(provider_metadata=provider_metadata, [client configuration])
```

See the OpenID Connect specification for more information about the
[provider metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

#### Customizing authentication request parameters
To customize the [authentication request parameters](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest),
use `auth_request_params` in `ProviderConfiguration`:
```python
auth_params = {'scope': ['openid', 'profile']} # specify the scope to request
config = ProviderConfiguration([provider/client config], auth_request_params=auth_params)
```

#### Static client registration

If you have already registered a client with the provider, specify the client credentials directly:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata

client_metadata = ClientMetadata(client_id='cl41ekfb9j', client_secret='m1C659wLipXfUUR50jlZ')
config = ProviderConfiguration([provider configuration], client_metadata=client_metadata)
```

**Note: The redirect URIs registered with the provider MUST include `<application_url>/redirect_uri`,
where `<application_url>` is the URL of the Flask application.**
To configure this extension to use a different endpoint, set the
[`OIDC_REDIRECT_ENDPOINT` configuration parameter](#flask-configuration).

#### Dynamic client registration

To dynamically register a new client for your application, the required client registration info can be specified:

```python
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientRegistrationInfo

client_registration_info = ClientRegistrationInfo(client_name='Test App', contacts=['dev@rp.example.com'])
config = ProviderConfiguration([provider configuration], client_registration_info=client_registration_info)
```

### Flask configuration

The application using this extension **MUST** set the following
[builtin configuration values of Flask](http://flask.pocoo.org/docs/config/#builtin-configuration-values):

* `SERVER_NAME`: **MUST** be the same as `<flask_url>` if using static client registration.
* `SECRET_KEY`: This extension relies on [Flask sessions](http://flask.pocoo.org/docs/quickstart/#sessions), which
   requires `SECRET_KEY`.

You may also configure the way the user sessions created by this extension are handled:

* `OIDC_SESSION_PERMANENT`: If set to `True` (which is the default) the user session will be kept until the configured
  session lifetime (see below). If set to `False` the session will be deleted when the user closes the browser.
* `OIDC_REDIRECT_ENDPOINT`: Set the endpoint used as redirect_uri to receive authentication responses. Defaults to
  `redirect_uri`, meaning the URL `<application_url>/redirect_uri` needs to be registered with the provider(s).
* `PERMANENT_SESSION_LIFETIME`: Control how long a user session is valid, see
  [Flask documentation](http://flask.pocoo.org/docs/1.0/config/#PERMANENT_SESSION_LIFETIME) for more information.

### Session refresh

If your provider supports the `prompt=none` authentication request parameter, this extension can automatically refresh
user sessions. This ensures that the user attributes (OIDC claims, user being active, etc.) are kept up-to-date without
having to log the user out and back in. To enable and configure the feature, specify the interval (in seconds) between
refreshes:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration

config = ProviderConfiguration(session_refresh_interval_seconds=1800, [provider/client config]
```

**Note: The user will still be logged out when the session expires (as described above).**

## Protect an endpoint by authentication

To add authentication to one of your endpoints use the `oidc_auth` decorator:
```python
import flask
from flask import Flask, jsonify

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
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

After a successful login, this extension will place three things in the user session (if they are received from the
provider):
* [ID Token](http://openid.net/specs/openid-connect-core-1_0.html#IDToken)
* [Access Token](http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)
* [Userinfo Response](http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)

### Using multiple providers

To allow users to login with multiple different providers, configure all of them in the `OIDCAuthentication`
constructor and specify which one to use by name for each endpoint:
```python
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration

app = Flask(__name__)
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
