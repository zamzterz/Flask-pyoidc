import flask
from flask import Flask, jsonify

from flask_pyoidc.flask_pyoidc import OIDCAuthentication

PORT = 5000
app = Flask(__name__)

app.config.update({'SERVER_NAME': 'localhost:{}'.format(PORT),
                   'SECRET_KEY': 'dev_key'})
auth = OIDCAuthentication(app, issuer="https://localhost:50009")


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
