from django.core.cache import cache
from django_redis import get_redis_connection
import json
import hashlib
import logging

logger = logging.getLogger(__name__)

class RedisCacheService:
    """
    Redis-optimized Cache Service
    """
    
    def __init__(self, alias='default'):
        self.cache = cache
        try:
            self.redis_conn = get_redis_connection(alias)
            self.redis_available = True
        except Exception as e:
            logger.warning(f"Redis connection failed, falling back to default cache: {e}")
            self.redis_available = False
    
    def _make_key(self, prefix, *args):
        """
        ইউনিক ক্যাশ কী জেনারেট
        """
        key_parts = [prefix]
        key_parts.extend([str(arg) for arg in args])
        key_string = ':'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def set(self, key, value, timeout=300):
        """
        ক্যাশে ডাটা সেট করা
        timeout: সেকেন্ড (ডিফল্ট ৫ মিনিট)
        """
        try:
            # JSON সিরিয়ালাইজ করা (যদি ডিকশনারি বা লিস্ট হয়)
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            
            if self.redis_available:
                # Redis specific - pipeline for better performance
                pipe = self.redis_conn.pipeline()
                pipe.set(key, value)
                pipe.expire(key, timeout)
                pipe.execute()
            else:
                # Fallback to default cache
                self.cache.set(key, value, timeout)
            
            return True
            
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    def get(self, key, default=None):
        """
        ক্যাশ থেকে ডাটা পাওয়া
        """
        try:
            if self.redis_available:
                value = self.redis_conn.get(key)
                if value:
                    try:
                        # JSON ডিকোড করার চেষ্টা
                        return json.loads(value.decode('utf-8'))
                    except (json.JSONDecodeError, AttributeError):
                        return value.decode('utf-8') if value else default
            else:
                # Fallback to default cache
                value = self.cache.get(key)
                if value and isinstance(value, str):
                    try:
                        return json.loads(value)
                    except json.JSONDecodeError:
                        return value
                return value or default
            
            return default
            
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return default
    
    def delete(self, key):
        """
        ক্যাশ থেকে ডাটা ডিলিট
        """
        try:
            if self.redis_available:
                return self.redis_conn.delete(key)
            else:
                return self.cache.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    def increment(self, key, delta=1, timeout=300):
        """
        ক্যাশ ভ্যালু ইনক্রিমেন্ট (Redis atomic operation)
        """
        try:
            if self.redis_available:
                # Redis INCR is atomic
                value = self.redis_conn.incr(key, delta)
                # Set expiry if this is a new key
                if value == delta:
                    self.redis_conn.expire(key, timeout)
                return value
            else:
                # Fallback
                current = self.get(key, 0)
                new_value = current + delta
                self.set(key, new_value, timeout)
                return new_value
                
        except Exception as e:
            logger.error(f"Cache increment error: {e}")
            return 1
    
    def get_or_set(self, key, callback, timeout=300):
        """
        ক্যাশে না থাকলে callback কল করে সেট করে রিটার্ন
        """
        value = self.get(key)
        if value is None:
            value = callback()
            self.set(key, value, timeout)
        return value
    
    def clear_pattern(self, pattern):
        """
        প্যাটার্ন অনুযায়ী ক্যাশ ক্লিয়ার (Redis only)
        """
        if not self.redis_available:
            logger.warning("Pattern clear not supported without Redis")
            return False
        
        try:
            keys = self.redis_conn.keys(pattern)
            if keys:
                return self.redis_conn.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Pattern clear error: {e}")
            return False
    
    def expire(self, key, timeout):
        """
        ক্যাশের মেয়াদ সেট করা
        """
        try:
            if self.redis_available:
                return self.redis_conn.expire(key, timeout)
            else:
                # Not directly supported in default cache
                value = self.get(key)
                if value is not None:
                    self.set(key, value, timeout)
                return True
        except Exception as e:
            logger.error(f"Expire error: {e}")
            return False
    
    def ttl(self, key):
        """
        ক্যাশের বাকি সময় জানতে
        """
        try:
            if self.redis_available:
                return self.redis_conn.ttl(key)
            else:
                return None
        except Exception as e:
            logger.error(f"TTL error: {e}")
            return None


class LoginAttemptCache:
    """
    লগইন অ্যাটেম্পট ট্র্যাক করার জন্য Redis-optimized ক্যাশ
    """
    
    def __init__(self):
        self.cache = RedisCacheService('rate_limit')  # Use rate_limit cache
    
    def get_failed_attempts(self, email, ip_address):
        """
        ব্যর্থ প্রচেষ্টা সংখ্যা পাওয়া
        """
        key = self.cache._make_key('failed_login', email, ip_address)
        return self.cache.get(key, 0)
    
    def increment_failed_attempts(self, email, ip_address, timeout=900):
        """
        ব্যর্থ প্রচেষ্টা ইনক্রিমেন্ট (১৫ মিনিট)
        """
        key = self.cache._make_key('failed_login', email, ip_address)
        return self.cache.increment(key, timeout=timeout)
    
    def reset_failed_attempts(self, email, ip_address):
        """
        ব্যর্থ প্রচেষ্টা রিসেট
        """
        key = self.cache._make_key('failed_login', email, ip_address)
        return self.cache.delete(key)
    
    def is_account_locked(self, user_id):
        """
        অ্যাকাউন্ট লকড কিনা চেক
        """
        key = self.cache._make_key('account_locked', user_id)
        return self.cache.get(key, False)
    
    def lock_account(self, user_id, timeout=1800):
        """
        অ্যাকাউন্ট লক করা (৩০ মিনিট)
        """
        key = self.cache._make_key('account_locked', user_id)
        return self.cache.set(key, True, timeout)


class OTPCache:
    """
    OTP স্টোর করার জন্য Redis-optimized ক্যাশ
    """
    
    def __init__(self):
        self.cache = RedisCacheService('default')
    
    def store_otp(self, user_id, otp, timeout=300):
        """
        OTP ক্যাশে সংরক্ষণ (৫ মিনিট)
        """
        key = self.cache._make_key('otp', user_id)
        return self.cache.set(key, otp, timeout)
    
    def get_otp(self, user_id):
        """
        OTP পাওয়া
        """
        key = self.cache._make_key('otp', user_id)
        return self.cache.get(key)
    
    def verify_otp(self, user_id, otp):
        """
        OTP ভেরিফাই (একবার ব্যবহারের পর ডিলিট)
        """
        stored_otp = self.get_otp(user_id)
        if stored_otp and str(stored_otp) == str(otp):
            self.delete_otp(user_id)
            return True
        return False
    
    def delete_otp(self, user_id):
        """
        OTP ডিলিট
        """
        key = self.cache._make_key('otp', user_id)
        return self.cache.delete(key)
    
    def get_failed_attempts(self, user_id):
        """
        ব্যর্থ OTP প্রচেষ্টা
        """
        key = self.cache._make_key('failed_otp', user_id)
        return self.cache.get(key, 0)
    
    def increment_failed_attempts(self, user_id, timeout=900):
        """
        ব্যর্থ OTP প্রচেষ্টা ইনক্রিমেন্ট
        """
        key = self.cache._make_key('failed_otp', user_id)
        return self.cache.increment(key, timeout=timeout)
    
    def reset_failed_attempts(self, user_id):
        """
        ব্যর্থ OTP প্রচেষ্টা রিসেট
        """
        key = self.cache._make_key('failed_otp', user_id)
        return self.cache.delete(key)


class TempTokenCache:
    """
    টেম্পোরারি টোকেন স্টোর করার জন্য Redis-optimized ক্যাশ
    """
    
    def __init__(self):
        self.cache = RedisCacheService('default')
    
    def store_token(self, user_id, token, timeout=300):
        """
        টেম্পোরারি টোকেন সংরক্ষণ
        """
        key = self.cache._make_key('temp_token', user_id, token[:10])
        return self.cache.set(key, token, timeout)
    
    def verify_token(self, user_id, token):
        """
        টোকেন ভেরিফাই
        """
        key = self.cache._make_key('temp_token', user_id, token[:10])
        stored_token = self.cache.get(key)
        if stored_token and stored_token == token:
            self.cache.delete(key)
            return True
        return False


class RateLimiter:
    """
    রেট লিমিটিং এর জন্য Redis-optimized ক্লাস
    """
    
    def __init__(self, cache_alias='rate_limit'):
        self.cache = RedisCacheService(cache_alias)
    
    def check_rate_limit(self, key, max_attempts, period=60):
        """
        রেট লিমিট চেক
        key: ইউনিক আইডি (যেমন IP, user_id)
        max_attempts: সর্বোচ্চ অনুমোদিত প্রচেষ্টা
        period: সময়কাল (সেকেন্ড)
        """
        current = self.cache.increment(key, timeout=period)
        return current <= max_attempts, current, max_attempts
    
    def get_remaining_attempts(self, key, max_attempts):
        """
        বাকি প্রচেষ্টা সংখ্যা
        """
        current = self.cache.get(key, 0)
        return max(0, max_attempts - current)
    
    def reset(self, key):
        """
        রেট লিমিটার রিসেট
        """
        return self.cache.delete(key)