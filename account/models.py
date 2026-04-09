from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from .managers import *
import pyotp
import uuid
from django.utils import timezone  # top level import



class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, db_index=True)
    email = models.EmailField(db_index=True, max_length=150, unique=True)
    phone = models.CharField(max_length=20)
    
    # Personal info
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    
    # 2FA related fields
    is_2fa_enabled = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32)
    two_factor_enabled_at = models.DateTimeField(null=True, blank=True)
    
    # IP and device tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_login_device = models.CharField(max_length=255, blank=True)
    last_login_browser = models.CharField(max_length=100, blank=True)
    last_login_os = models.CharField(max_length=100, blank=True)
    last_login_location = models.CharField(max_length=255, blank=True)
    
    # IP restriction
    is_ip_restricted = models.BooleanField(default=False)
    allowed_ips = models.TextField(blank=True, help_text="Comma separated IP addresses")
    
    # Account status
    is_locked = models.BooleanField(default=False)
    locked_until = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    
    # Django required fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # অ্যাডমিন প্যানেল এক্সেসের জন্য
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # ইউজার ম্যানেজার সেট করা
    objects = CustomUserManager()
    
    # লগইনের জন্য ইউজারনেম ফিল্ড না করে ইমেইল ব্যবহার করা
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'phone']  # createsuperuser কমান্ডে এই ফিল্ডগুলো চাইবে
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['username']),
            models.Index(fields=['phone']),
            models.Index(fields=['is_active', 'is_locked']),
        ]
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """Returns full name"""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name or self.username
    
    def get_short_name(self):
        """Returns short name"""
        return self.first_name or self.username
    

    
    def verify_otp(self, otp):
        try:

            totp = pyotp.TOTP(self.otp_secret, interval=300)
            return totp.verify(otp)
        except Exception:
            return False
    
    def get_allowed_ips_list(self):
        if self.allowed_ips:
            return [ip.strip() for ip in self.allowed_ips.split(',') if ip.strip()]
        return []
    

    def increment_failed_attempts(self, max_attempts=5, lockout_duration=1800):
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= max_attempts:
            self.is_locked = True
            
            # lockout_duration কে integer এ convert করুন
            try:
                if lockout_duration is None:
                    lock_duration = 1800
                else:
                    lock_duration = int(lockout_duration)
            except (ValueError, TypeError):
                lock_duration = 1800
            
            # সেফটি চেক
            lock_duration = max(60, min(lock_duration, 86400))  # 1 min to 24 hours
            
            self.locked_until = timezone.now() + timezone.timedelta(
                seconds=lock_duration
            )
        
        self.save()
        return self.failed_login_attempts
    
    
    def reset_failed_attempts(self):
        """
        Reset failed login attempts
        """
        self.failed_login_attempts = 0
        self.is_locked = False
        self.locked_until = None
        self.save()

