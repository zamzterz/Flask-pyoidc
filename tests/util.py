from jwkest.jwk import SYMKey
from oic import rndstr
from oic.oic import AccessTokenResponse, IdToken

signing_key = SYMKey(alg='HS256', key=rndstr(), kid=rndstr())


def signed_id_token(claims):
    id_token = IdToken(**claims)
    jws = id_token.to_jwt(key=[signing_key], algorithm=signing_key.alg)
    return jws, signing_key


def signed_access_token(claims):
    access_token = AccessTokenResponse(**claims)
    access_token.jws_header = {'alg': signing_key.alg}
    return access_token.to_jwt(key=[signing_key], algorithm=signing_key.alg)
