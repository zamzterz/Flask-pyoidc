# Configuration

## Provider and client configuration

Both static and dynamic provider configuration discovery, as well as static
and dynamic client registration, is supported. The different modes of provider configuration can be combined with any
of the client registration modes.

### Provider configuration

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

#### Session refresh

If your provider supports the `prompt=none` authentication request parameter, this extension can automatically refresh
user sessions. This ensures that the user attributes (OIDC claims, user being active, etc.) are kept up-to-date without
having to log the user out and back in. To enable and configure the feature, specify the interval (in seconds) between
refreshes:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration

config = ProviderConfiguration(session_refresh_interval_seconds=1800, [provider/client config])
```

**Note: The user will still be logged out when the session expires (as set in the Flask session configuration).**

### Client configuration

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

## Flask configuration

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
