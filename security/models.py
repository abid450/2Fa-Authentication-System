from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth import get_user_model
import uuid

User = get_user_model()

class LoginHistory(models.Model):
    """
    Login History Tracking Model
    """
    DEVICE_TYPES = [
        ('mobile', 'Mobile'),
        ('tablet', 'Tablet'),
        ('pc', 'PC'),
        ('bot', 'Bot'),
        ('other', 'Other'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='login_history'
    )
    ip_address = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    browser = models.CharField(max_length=100)
    browser_version = models.CharField(max_length=50, blank=True)
    os = models.CharField(max_length=100)
    os_version = models.CharField(max_length=50, blank=True)
    device_type = models.CharField(
        max_length=50, 
        choices=DEVICE_TYPES, 
        default='other'
    )
    location = models.CharField(max_length=255, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    is_successful = models.BooleanField(default=True)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    session_id = models.CharField(max_length=100, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-login_time']
        verbose_name = "Login History"
        verbose_name_plural = "Login Histories"
        indexes = [
            models.Index(fields=['user', 'login_time']),
            models.Index(fields=['ip_address', 'login_time']),
            models.Index(fields=['session_id']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address} - {self.login_time}"


class SuspiciousActivity(models.Model):
    """
    Suspicious Activity Tracking Model
    """
    ACTIVITY_TYPES = [
        ('MULTIPLE_FAILED', 'Multiple Failed Logins'),
        ('NEW_IP', 'New IP Login'),
        ('UNUSUAL_TIME', 'Unusual Time Login'),
        ('DEVICE_CHANGE', 'Device Change'),
        ('LOCATION_CHANGE', 'Location Change'),
        ('RAPID_ATTEMPTS', 'Rapid Login Attempts'),
    ]
    
    SEVERITY_LEVELS = [
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
        (4, 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='suspicious_activities'
    )
    activity_type = models.CharField(
        max_length=50, 
        choices=ACTIVITY_TYPES
    )
    ip_address = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    browser = models.CharField(max_length=100, blank=True)
    os = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict)
    severity = models.IntegerField(choices=SEVERITY_LEVELS, default=1)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='resolved_activities'
    )
    resolution_note = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Suspicious Activity"
        verbose_name_plural = "Suspicious Activities"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_resolved']),
            models.Index(fields=['activity_type', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.get_activity_type_display()} - {self.created_at}"


# IPWhitelist -----------------------------------------------------------------
class IPWhitelist(models.Model):
    """
    IP Whitelist Model
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='ip_whitelist'
    )
    ip_address = models.GenericIPAddressField()
    description = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'ip_address']
        verbose_name = "IP Whitelist"
        verbose_name_plural = "IP Whitelists"
        indexes = [
            models.Index(fields=['user', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"



class SecurityAuditLog(models.Model):
    """
    Security Audit Log
    """
    EVENT_TYPES = [
        ('LOGIN_SUCCESS', 'Login Successful'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('PASSWORD_CHANGE', 'Password Changed'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('2FA_ENABLED', '2FA Enabled'),
        ('2FA_DISABLED', '2FA Disabled'),
        ('IP_WHITELIST_ADD', 'IP Whitelist Added'),
        ('IP_WHITELIST_REMOVE', 'IP Whitelist Removed'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('ACCOUNT_UNLOCKED', 'Account Unlocked'),
        ('PROFILE_UPDATED', 'Profile Updated'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='audit_logs'
    )
    event_type = models.CharField(
        max_length=50, 
        choices=EVENT_TYPES
    )
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    device = models.CharField(max_length=255, blank=True)
    browser = models.CharField(max_length=100, blank=True)
    os = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Security Audit Log"
        verbose_name_plural = "Security Audit Logs"
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['event_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username if self.user else 'Unknown'} - {self.get_event_type_display()} - {self.timestamp}"