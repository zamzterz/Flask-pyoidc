import flask
import logging
from flask import Flask, jsonify

from flask_pyoidc.flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
# See http://flask.pocoo.org/docs/0.12/config/
app.config.update({'SERVER_NAME': 'localhost:5000',
                   'SECRET_KEY': 'dev_key',  # make sure to change this!!
                   'PREFERRED_URL_SCHEME': 'http',
                   'SESSION_PERMANENT': True,  # turn on flask session support
                   'PERMANENT_SESSION_LIFETIME': 2592000,  # session time in seconds (30 days)
                   'DEBUG': True})

ISSUER = 'https://provider.example.com'
CLIENT_ID = 'client1'
CLIENT_SECRET = 'very_secret'
provider_configuration = ProviderConfiguration(issuer=ISSUER,
                                               client_metadata=ClientMetadata(CLIENT_ID, CLIENT_SECRET))
auth = OIDCAuthentication(provider_configuration)


@app.route('/')
@auth.oidc_auth
def index():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/logout')
@auth.oidc_logout
def logout():
    return "You've been successfully logged out!"


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run()
