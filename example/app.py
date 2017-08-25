import flask
from flask import Flask, jsonify

from flask_pyoidc.flask_pyoidc import OIDCAuthentication

PORT = 5000
app = Flask(__name__)


# See http://flask.pocoo.org/docs/0.12/config/
app.config.update({'SERVER_NAME': 'example.com',
                   'SECRET_KEY': 'dev_key',
                   'PREFERRED_URL_SCHEME': 'https',
                   'SESSION_PERMANENT': True, # turn on flask session support
                   'PERMANENT_SESSION_LIFETIME': 2592000, # session time in seconds (30 days)
                   'DEBUG': True})

auth = OIDCAuthentication(app, issuer="auth.example.net")

@app.route('/')
@auth.oidc_auth
def index():
    return jsonify(id_token=flask.session['id_token'], access_token=flask.session['access_token'],
                   userinfo=flask.session['userinfo'])


@app.route('/logout')
@auth.oidc_logout
def logout():
    return 'You\'ve been successfully logged out!'


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    app.run(port=PORT)
