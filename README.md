# Flask-pyoidc

[![PyPI](https://img.shields.io/pypi/v/flask-pyoidc.svg)](https://pypi.python.org/pypi/Flask-pyoidc)
[![codecov.io](https://codecov.io/github/its-dirg/Flask-pyoidc/coverage.svg?branch=master)](https://codecov.io/github/its-dirg/Flask-pyoidc?branch=master)

This repository contains an example of how to use the [pyoidc](https://github.com/rohe/pyoidc)
library to provide simple OpenID Connect authentication (using the ["Code Flow"](http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)).

## Usage

The extension support both static and dynamic provider configuration discovery as well as static
and dynamic client registration. The different modes of provider configuration can be combined in
any way with the different client registration modes.

* Static provider configuration: `OIDCAuthentication(provider_configuration_info=provider_config)`,
  where `provider_config` is a dictionary containing the [provider metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
* Dynamic provider configuration: `OIDCAuthentication(issuer=issuer_url)`, where `issuer_url`
  is the issuer URL of the provider.
* Static client registration: `OIDCAuthentication(client_registration_info=client_info)`, where
  `client_info` is all the [registered metadata](https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse)
  about the client. The `redirect_uris` registered with the provider MUST include
  `<flask_url>/redirect_uri`, where `<flask_url>` is the URL for the Flask application.

## Configuration

The application using this extension MUST set the following [builtin configuration values of Flask](http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values):

* `SERVER_NAME` (MUST be the same as `<flask_url>` if using static client registration)
* `SECRET_KEY` (this extension relies on [Flask sessions](http://flask.pocoo.org/docs/0.11/quickstart/#sessions), which requires `SECRET_KEY`)

You may also configure the way Flask sessions handles the user session:

* `PERMANENT_SESSION` (added by this extension; makes the session cookie expire after a configurable length of time instead of being tied to the browser session)
* `PERMANENT_SESSION_LIFETIME` (the lifetime of a permanent session)

See the [Flask documentation](http://flask.pocoo.org/docs/0.11/config/#builtin-configuration-values) for an exhaustive list of configuration options.

## Example

Have a look at the example Flask app in [app.py](example/app.py) for an idea of how to use it.
