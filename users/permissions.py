from rest_framework.permissions import BasePermission

class IsHostUser(BasePermission):

    def has_permission(self, request, view):

        return (
            request.user.is_authenticated and
            hasattr(request.user, 'host_profile') and
            request.user.host_profile.is_host
        )