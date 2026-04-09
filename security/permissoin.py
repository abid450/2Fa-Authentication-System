from rest_framework import permissions

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    নিজের ডাটা বা অ্যাডমিন পারমিশন
    - সাধারণ ইউজার শুধু নিজের ডাটা দেখতে পারবে
    - অ্যাডমিন সব ডাটা দেখতে পারবে
    """
    
    def has_object_permission(self, request, view, obj):
        # অ্যাডমিন সব পাবে
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # ইউজার তার নিজের ডাটা পাবে
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'id'):
            return obj == request.user
        
        return False


class IsOwner(permissions.BasePermission):
    """
    শুধু নিজের ডাটা এক্সেস (অ্যাডমিনও পাবে না)
    """
    
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'id'):
            return obj == request.user
        return False


class IsAdminOnly(permissions.BasePermission):
    """
    শুধু অ্যাডমিন এক্সেস
    """
    
    def has_permission(self, request, view):
        return bool(request.user and (request.user.is_staff or request.user.is_superuser))


class IsActiveUser(permissions.BasePermission):
    """
    শুধু সক্রিয় ইউজার এক্সেস
    """
    
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_active and not request.user.is_locked)


class Has2FAEnabled(permissions.BasePermission):
    """
    2FA চালু থাকলে এক্সেস
    """
    
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_2fa_enabled)


class IPWhitelistPermission(permissions.BasePermission):
    """
    IP হোয়াইটলিস্ট পারমিশন
    """
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return True
        
        # যদি IP রেস্ট্রিকশন না থাকে
        if not request.user.is_ip_restricted:
            return True
        
        from security.service import IPMonitoringService
        ip_address = IPMonitoringService.get_client_ip(request)
        
        # অনুমোদিত IP লিস্ট চেক
        allowed_ips = request.user.get_allowed_ips_list()
        if ip_address in allowed_ips:
            return True
        
        # IP হোয়াইটলিস্ট চেক
        from security.models import IPWhitelist
        return IPWhitelist.objects.filter(
            user=request.user,
            ip_address=ip_address,
            is_active=True
        ).exists()


class IsSameCompany(permissions.BasePermission):
    """
    একই কোম্পানির ইউজার চেক
    """
    
    def has_object_permission(self, request, view, obj):
        if not request.user.is_authenticated:
            return False
        
        if hasattr(obj, 'company'):
            return obj.company == request.user.company
        elif hasattr(obj, 'user') and hasattr(obj.user, 'company'):
            return obj.user.company == request.user.company
        return False


class CanManage2FA(permissions.BasePermission):
    """
    2FA ম্যানেজ করার পারমিশন
    """
    
    def has_object_permission(self, request, view, obj):
        # নিজের 2FA নিজে ম্যানেজ করতে পারবে
        if obj == request.user:
            return True
        
        # অ্যাডমিন অন্যর 2FA ম্যানেজ করতে পারবে না (নিরাপত্তার জন্য)
        return False


class ReadOnly(permissions.BasePermission):
    """
    শুধু পড়ার অনুমতি (GET, HEAD, OPTIONS)
    """
    
    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS