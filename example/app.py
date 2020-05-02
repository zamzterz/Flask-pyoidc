import datetime
import flask
import logging
from flask import Flask, jsonify

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
# See http://flask.pocoo.org/docs/0.12/config/
app.config.update({'OIDC_REDIRECT_URI': 'http://localhost:5000/redirect_uri',
                   'SECRET_KEY': 'dev_key',  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': True})

ISSUER1 = 'https://provider1.example.com'
CLIENT1 = 'client@provider1'
PROVIDER_NAME1 = 'provider1'
PROVIDER_CONFIG1 = ProviderConfiguration(issuer=ISSUER1,
                                         client_metadata=ClientMetadata(CLIENT1, 'secret1'))
ISSUER2 = 'https://provider2.example.com'
CLIENT2 = 'client@provider2'
PROVIDER_NAME2 = 'provider2'
PROVIDER_CONFIG2 = ProviderConfiguration(issuer=ISSUER2,
                                         client_metadata=ClientMetadata(CLIENT2, 'secret2'))
auth = OIDCAuthentication({PROVIDER_NAME1: PROVIDER_CONFIG1, PROVIDER_NAME2: PROVIDER_CONFIG2})


@app.route('/')
@auth.oidc_auth(PROVIDER_NAME1)
def login1():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/login2')
@auth.oidc_auth(PROVIDER_NAME2)
def login2():
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
