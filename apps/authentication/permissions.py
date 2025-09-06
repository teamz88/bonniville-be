from rest_framework import permissions


class IsAdminUser(permissions.BasePermission):
    """Permission class to check if user is admin."""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_admin
        )


class IsOwnerOrAdmin(permissions.BasePermission):
    """Permission class to check if user is owner of object or admin."""
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Admin users can access any object
        if request.user.is_admin:
            return True
        
        # Check if object has a user field and user owns it
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        # Check if object is the user itself
        if hasattr(obj, 'id') and hasattr(request.user, 'id'):
            return obj.id == request.user.id
        
        return False


class IsActiveSubscription(permissions.BasePermission):
    """Permission class to check if user has active subscription."""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            (request.user.is_admin or request.user.is_subscription_active)
        )


class IsPremiumUser(permissions.BasePermission):
    """Permission class to check if user has premium subscription."""
    
    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            (
                request.user.is_admin or
                request.user.subscription_type in [
                    request.user.SubscriptionType.PREMIUM,
                    request.user.SubscriptionType.LIFETIME
                ]
            )
        )