from oic.oauth2.message import AccessTokenResponse, CCAccessTokenRequest, MessageTuple, OauthMessageFactory


class CCMessageFactory(OauthMessageFactory):
    """Client Credential Request Factory."""
    token_endpoint = MessageTuple(CCAccessTokenRequest, AccessTokenResponse)
