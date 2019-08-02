from django.core.cache import caches
from functools import partial
from rest_framework.authentication import TokenAuthentication


locmem_cache = caches["locmem"]


class CachedTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        """
        Does a cached lookup for a user for the given token
        """
        return locmem_cache.get_or_set(
            "authtoken:{}".format(key), partial(super().authenticate_credentials, key)
        )
