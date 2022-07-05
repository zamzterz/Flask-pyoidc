import time

import cachetools
from oic.extension.message import TokenIntrospectionResponse


class TokenIntrospectionCacheFactory(cachetools.TTLCache):
    """Time aware caching factory for token introspection parameters and response."""
    def __setitem__(self, key, token_introspection_response: TokenIntrospectionResponse) -> None:
        """Stores cache of token introspection.

        Parameters
        ----------
        key: cachetools.keys._HashedTuple
            Token introspection parameters.
        token_introspection_response: TokenIntrospectionResponse

        Notes
        -----
        To maintain user security, the cached access token must be purged at
        the expiry time of access token or at the expiry time of cache itself
        or whatever happens first. This method sets custom ttl for the cache,
        based on what happens first.
        """
        time_to_live = self.ttl
        if token_introspection_response.get('active', False):
            expires_in_seconds = token_introspection_response['exp'] - time.time()
            if expires_in_seconds < time_to_live:
                # Set the attribute to the expiry time of access token.
                self._TTLCache__ttl = expires_in_seconds
        super().__setitem__(key, token_introspection_response)
        # Revert the value of the attribute to the one provided by the user.
        self._TTLCache__ttl = time_to_live
