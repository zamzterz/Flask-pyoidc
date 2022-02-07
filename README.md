# Flask-pyoidc

[![PyPI](https://img.shields.io/pypi/v/flask-pyoidc.svg)](https://pypi.python.org/pypi/Flask-pyoidc)
[![codecov.io](https://codecov.io/github/zamzterz/Flask-pyoidc/coverage.svg?branch=master)](https://codecov.io/github/its-dirg/Flask-pyoidc?branch=master)
[![Build Status](https://travis-ci.org/zamzterz/Flask-pyoidc.svg?branch=master)](https://travis-ci.org/zamzterz/Flask-pyoidc)

This Flask extension provides simple OpenID Connect authentication, backed by [pyoidc](https://github.com/rohe/pyoidc).

["Authorization Code Flow"](http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
["Implicit Flow"](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth),
["Hybrid Flow"](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth),
["Client Credentials Flow"](https://oauth.net/2/grant-types/client-credentials/) are supported.

## Getting started
Read [the documentation](https://flask-pyoidc.readthedocs.io/) or have a look at the
[example Flask app](example/app.py) for a full example of how to use this extension.

Below is a basic example of how to get started:
```python
app = Flask(__name__)
app.config.update(
    OIDC_REDIRECT_URI = 'https://example.com/redirect_uri',
    SECRET_KEY = ...
)

# Static Client Registration
client_metadata = ClientMetadata(
    client_id='client1',
    client_secret='secret1',
    post_logout_redirect_uris=['https://example.com/logout'])


provider_config = ProviderConfiguration(issuer='<issuer URL of provider>',
                                        client_metadata=client_metadata)

auth = OIDCAuthentication({'default': provider_config}, app)

@app.route('/')
@auth.oidc_auth('default') # endpoint will require login
def index():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)
```
