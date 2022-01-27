# Configuration

Both static and dynamic provider configuration discovery, as well as static and dynamic client registration, is
supported. The different modes of provider configuration can be combined with any of the client registration modes.

## Client Configuration
---

### Static Client Registration

If you have already registered a client with the provider, specify the client credentials directly:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata

client_metadata = ClientMetadata(client_id='client1', client_secret='secret1')
```

**Note: The redirect URIs registered with the provider MUST include the URI specified in
[`OIDC_REDIRECT_URI`](https://flask.palletsprojects.com/en/2.0.x/config/).**


### Dynamic Client Registration

To dynamically register a new client for your application, the required client registration info can be specified:

```python
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientRegistrationInfo

client_registration_info = ClientRegistrationInfo(client_name='Test App', contacts=['dev@example.com'])
```

## Provider configuration
---

### Dynamic provider configuration

To use a provider which supports dynamic discovery it suffices to specify the issuer URL:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration

# If you are using Static Client Configuration, then specify client_metadata
# as shown above.
provider_config = ProviderConfiguration(issuer='https://idp.example.com',
                                        client_metadata=client_metadata)

# If you are using Dynamic Client Registration, then specify
# client_registration_info as shown above.
provider_config = ProviderConfiguration(issuer='https://idp.example.com',
                                        client_registration_info=client_registration_info)
```

### Static provider configuration

To use a provider not supporting dynamic discovery, the static provider metadata can be specified:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata

provider_metadata = ProviderMetadata(issuer='https://idp.example.com',
                                     authorization_endpoint='https://idp.example.com/auth',
                                     token_endpoint='https://idp.example.com/token',
                                     introspection_endpoint='https://idp.example.com/introspect',
                                     userinfo_endpoint='https://idp.example.com/userinfo',
                                     end_session_endpoint='https://idp.example.com/logout',
                                     jwks_uri='https://idp.example.com/certs',
                                     registration_endpoint='https://idp.example.com/registration'
                                     )
# As shown earlier, if you are using Static Client Configuration, then specify
# client_metadata.
provider_config = ProviderConfiguration(provider_metadata=provider_metadata,
                                        client_metadata=client_metadata)

# If you are using Dynamic Client Registration, then specify
# client_registration_info.
provider_config = ProviderConfiguration(provider_metadata=provider_metadata,
                                        client_registration_info=client_registration_info)
```

See the OpenID Connect specification for more information about the
[provider metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

As mentioned in OpenID Connect specification, `userinfo_endpoint` is optional. If it's not provided, no userinfo
request will be done and `flask_pyoidc.UserSession.userinfo` will be set to `None`.  

### Customizing authentication request parameters
To customize the [authentication request parameters](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest),
use `auth_request_params` in `ProviderConfiguration`:
```python
auth_params = {'scope': ['openid', 'profile']} # specify the scope to request
provider_config = ProviderConfiguration([provider/client config], auth_request_params=auth_params)
```

### Session refresh

If your provider supports the `prompt=none` authentication request parameter, this extension can automatically refresh
user sessions. This ensures that the user attributes (OIDC claims, user being active, etc.) are kept up-to-date without
having to log the user out and back in. To enable and configure the feature, specify the interval (in seconds) between
refreshes:
```python
from flask_pyoidc.provider_configuration import ProviderConfiguration

provier_config = ProviderConfiguration(session_refresh_interval_seconds=1800, [provider/client config])
```

**Note: The user will still be logged out when the session expires (as set in the Flask session configuration).**

## Client Credentials Flow
The [Client Credentials](https://tools.ietf.org/html/rfc6749#section-4.4) grant type is used by clients to obtain an access token outside of the context of a user.

This is typically used by clients to access resources about themselves rather than to access a user's resources.

Client can obtain access token by using `client_credentials_grant`.

```python
auth = OIDCAuthentication({'default': provider_config}, app)

client_credentials_response = auth.clients['default'].client_credentials_grant()
access_token = resp.get('access_token')
```

Use the obtained `access_token` to access your web service APIs.
If your API endpoints are protected with `@auth.token_auth` or
`@auth.access_control`, `access_token` will be verfied by token introspection
before allowing access.

## Flask configuration

The application using this extension **MUST** set the following configuration parameters:

* `SECRET_KEY`: This extension relies on [Flask sessions](http://flask.pocoo.org/docs/quickstart/#sessions), which
   requires [`SECRET_KEY`](http://flask.pocoo.org/docs/config/#builtin-configuration-values).
* `OIDC_REDIRECT_URI`: The URI used as redirect URI to receive authentication responses. This extension will add a url
   rule to handle all requests to the specified endpoint, so make sure the domain correctly points to your app and that
   the URL path is not already used in the app.

This extension also uses the following configuration parameters:
* `OIDC_SESSION_PERMANENT`: If set to `True` (which is the default) the user session will be kept until the configured
  session lifetime (see below). If set to `False` the session will be deleted when the user closes the browser.
* `PERMANENT_SESSION_LIFETIME`: Control how long a user session is valid, see
  [Flask documentation](http://flask.pocoo.org/docs/1.0/config/#PERMANENT_SESSION_LIFETIME) for more information.

### Legacy configuration parameters
The following parameters have been deprecated:
* `OIDC_REDIRECT_DOMAIN`: Set the domain (which may contain port number) used in the redirect_uri to receive
  authentication responses. Defaults to the `SERVER_NAME` configured for Flask.
* `OIDC_REDIRECT_ENDPOINT`: Set the endpoint used in the redirect_uri to receive authentication responses. Defaults to
  `redirect_uri`, meaning the URL `<application_url>/redirect_uri` needs to be registered with the provider(s).
