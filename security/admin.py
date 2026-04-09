from django.contrib import admin
from .models import *
# Register your models here.
@admin.register(LoginHistory)
class LoginAdmin(admin.ModelAdmin):
    list_display = ['user', 'ip_address', 'device', 'browser', 'browser_version', 'os', 'os_version',
                    'device_type', 'location', 'latitude', 'longitude', 'login_time', 'logout_time', 'session_id',
                    'user_agent']


admin.site.register(SuspiciousActivity)
admin.site.register(IPWhitelist)

@admin.register(SecurityAuditLog)
class SecurityAdmin(admin.ModelAdmin):
    list_display = ['user', 'event_type', 'ip_address', 'user_agent', 'device', 'browser', 'os',
                    'location', 'details', 'timestamp']



