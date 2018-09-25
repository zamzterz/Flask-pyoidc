from jwkest.jwk import SYMKey
from oic import rndstr
from oic.oic import IdToken


def signed_id_token(claims):
    id_token = IdToken(**claims)
    signing_key = SYMKey(alg='HS256', key=rndstr())
    jws = id_token.to_jwt(key=[signing_key], algorithm=signing_key.alg)
    return jws, signing_key
