from rest_framework.permissions import SAFE_METHODS, BasePermission

class IsManagerUser(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_manager)

class IsMerchandiserUser(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_merchandiser)

class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        else:
            return request.user.is_staff
