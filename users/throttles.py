
from rest_framework.throttling import SimpleRateThrottle

class LoginRateThrottle(SimpleRateThrottle):
    
    scope = "login"

    def get_cache_key(self, request, view):
        return f"login_{self.get_ident(request)}"


class PasswordResetRateThrottle(SimpleRateThrottle):

    scope = "password_reset"

    def get_cache_key(self, request, view):

        return f"password_reset_{self.get_ident(request)}"