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
    return jsonify(id_token=flask.g.id_token.to_dict(), access_token=flask.g.access_token,
                   userinfo=flask.g.userinfo.to_dict())


if __name__ == '__main__':
    app.run(port=PORT)
