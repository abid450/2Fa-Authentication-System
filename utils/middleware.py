from django.utils import timezone
import logging
from security.service import IPMonitoringService
from .cache import CacheService


logger = logging.getLogger(__name__)

class IPLoggingMiddleware:
     """
    IP লগিং মিডলওয়্যার - প্রতিটি রিকোয়েস্টে IP এবং ডিভাইস ইনফো যোগ করে
    """
     
     def __init__(self, get_response):
          self.get_response = get_response
          self.ip_service = IPMonitoringService

     def __call__(self, request):
          request.client_ip = self.ip_service.get_client_ip(request)
          request.device_info = self.ip_service.get_device_info(request)

          response = self.get_response(request)

          return response
     

class RequestLoggingMiddleware:
     """
    রিকোয়েস্ট লগিং মিডলওয়্যার - সব রিকোয়েস্ট লগ করে
    """
     def __init__(self, get_response):
          self.get_response = get_response
     
     def __call__(self, request):
          start_time = timezone.now()
          response = self.get_response(request)

          duration = (timezone.now() - start_time).total_seconds()
          if not request.path.startswith('/admin/') and not request.path.startswith('/static/'):
               logger.info(
                f"{request.method} {request.path} - "
                f"IP: {getattr(request, 'client_ip', 'Unknown')} - "
                f"Status: {response.status_code} - "
                f"Duration: {duration:.2f}s"
            )
        
          return response
     


class RateLimitMiddleware:
    """
    রেট লিমিটিং মিডলওয়্যার (সিম্পল ভার্সন)
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.cache = CacheService()
    
    def __call__(self, request):
        # শুধু লগইন এবং OTP এন্ডপয়েন্টে রেট লিমিট প্রয়োগ করা হবে
        if request.path.endswith('/login/') or request.path.endswith('/verify-otp/'):
            ip = getattr(request, 'client_ip', '0.0.0.0')
            cache_key = f"rate_limit:{ip}:{request.path}"
            
            # গত ১ মিনিটে কতবার রিকোয়েস্ট এসেছে
            count = self.cache.get(cache_key, 0)
            
            if count > 10:  # প্রতি মিনিটে ১০ বার
                from django.http import JsonResponse
                return JsonResponse({
                    'status': 'error',
                    'message': 'অনেক বেশি রিকোয়েস্ট পাঠিয়েছেন। একটু পর আবার চেষ্টা করুন।'
                }, status=429)
            
            # কাউন্ট বাড়ানো
            self.cache.increment(cache_key, timeout=60)
        
        response = self.get_response(request)
        return response