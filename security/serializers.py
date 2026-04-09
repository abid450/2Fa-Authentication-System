from rest_framework import serializers
from .models import LoginHistory, SuspiciousActivity, IPWhitelist, SecurityAuditLog


# LoginHistory -----------------------------------------------
class LoginHistorySerializer(serializers.ModelSerializer):

    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = LoginHistory
        fields = [
            'id', 'username', 'email', 'ip_address', 'device',
            'browser', 'browser_version', 'os', 'os_version', 
            'device_type', 'location', 'is_successful',
            'login_time', 'logout_time'
        ]


class SuspiciousActivitySerializer(serializers.ModelSerializer):

    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    activity_type_display = serializers.CharField(
        source = 'get_activity_type_display', 
        read_only = True)
    
    severity_display = serializers.CharField(
        source='get_severity_display',
        read_only = True
    )

    class Meta:
        model = SuspiciousActivity
        fields = [
            'id', 'username', 'email', 'activity_type', 'activity_type_display', 'ip_address',
            'device', 'browser', 'os', 'location', 'details', 'severity', 'severity_display',
            'resolved_at', 'resolution_note', 'created_at'
        ]
    
    

class IPWhitelistSerializer(serializers.ModelSerializer):
    """
    IP হোয়াইটলিস্ট সিরিয়ালাইজার
    """
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = IPWhitelist
        fields = ['id', 'username', 'ip_address', 'description', 'is_active', 'created_at']
    
    def validate_ip_address(self, value):
        import ipaddress
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError("সঠিক IP অ্যাড্রেস দিন")
        return value


class SecurityAuditLogSerializer(serializers.ModelSerializer):
    """
    সিকিউরিটি অডিট লগ সিরিয়ালাইজার
    """
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    event_type_display = serializers.CharField(
        source='get_event_type_display', 
        read_only=True
    )
    
    class Meta:
        model = SecurityAuditLog
        fields = [
            'id', 'username', 'email', 'event_type', 'event_type_display',
            'ip_address', 'device', 'browser', 'os', 'location', 
            'details', 'timestamp'
        ]