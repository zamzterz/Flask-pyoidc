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
