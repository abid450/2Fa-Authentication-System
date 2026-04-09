from rest_framework.throttling import SimpleRateThrottle, AnonRateThrottle, UserRateThrottle
from django.core.cache import cache
import hashlib

class LoginRateThrottle(SimpleRateThrottle):
    """
    লগইন রেট থ্রটলিং - প্রতি ঘন্টায় ৫ বার
    """
    scope = 'login'
    
    def get_cache_key(self, request, view):
        # IP + Email কম্বিনেশন
        email = request.data.get('email', '')
        ident = self.get_ident(request)
        
        if email:
            key = hashlib.md5(f"{ident}:{email}".encode()).hexdigest()
        else:
            key = ident
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': key
        }
    
    def allow_request(self, request, view):
        # রেট লিমিট চেক করার আগে
        if request.method == 'POST':
            return super().allow_request(request, view)
        return True


class OTPRateThrottle(SimpleRateThrottle):
    """
    OTP ভেরিফিকেশন রেট থ্রটলিং - প্রতি ঘন্টায় ১০ বার
    """
    scope = 'otp'
    
    def get_cache_key(self, request, view):
        # IP + User ID কম্বিনেশন
        user_id = request.data.get('user_id', '')
        ident = self.get_ident(request)
        
        if user_id:
            key = hashlib.md5(f"{ident}:{user_id}".encode()).hexdigest()
        else:
            key = ident
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': key
        }


class IPBasedThrottle(SimpleRateThrottle):
    """
    IP ভিত্তিক থ্রটলিং - প্রতি মিনিটে ৬০ বার
    """
    scope = 'ip'
    
    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class UserBasedThrottle(UserRateThrottle):
    """
    ইউজার ভিত্তিক থ্রটলিং - প্রতি মিনিটে ১০০ বার
    """
    scope = 'user'
    
    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class RegistrationThrottle(SimpleRateThrottle):
    """
    রেজিস্ট্রেশন থ্রটলিং - প্রতি IP থেকে ঘন্টায় ৩ বার
    """
    scope = 'registration'
    
    def get_cache_key(self, request, view):
        ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class PasswordResetThrottle(SimpleRateThrottle):
    """
    পাসওয়ার্ড রিসেট থ্রটলিং - প্রতি ঘন্টায় ৩ বার
    """
    scope = 'password_reset'
    
    def get_cache_key(self, request, view):
        email = request.data.get('email', '')
        if email:
            key = hashlib.md5(email.encode()).hexdigest()
        else:
            key = self.get_ident(request)
        
        return self.cache_format % {
            'scope': self.scope,
            'ident': key
        }


class BurstRateThrottle(UserRateThrottle):
    """
    Burst protection - অল্প সময়ে অনেক রিকোয়েস্ট
    """
    scope = 'burst'
    
    def allow_request(self, request, view):
        # কাস্টম বার্স্ট প্রোটেকশন
        if request.user.is_authenticated:
            # গত ১০ সেকেন্ডে কত রিকোয়েস্ট?
            key = f"burst_{request.user.pk}"
            count = cache.get(key, 0)
            
            if count > 5:  # ১০ সেকেন্ডে ৫ বার
                return False
            
            cache.set(key, count + 1, 10)
        
        return super().allow_request(request, view)