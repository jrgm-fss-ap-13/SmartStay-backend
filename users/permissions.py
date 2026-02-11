from rest_framework.permissions import BasePermission

class IsHostUser(BasePermission):
    """
    Permite acceso solo a usuarios que tienen perfil de host activo
    """
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and
            hasattr(request.user, 'host_profile') and
            request.user.host_profile.is_active
        )