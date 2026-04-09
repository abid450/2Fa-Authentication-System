import pyotp
import requests
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from datetime import timedelta
from user_agents import parse
from celery import shared_task
import logging
import json
from account.models import *
from .models import *

logger = logging.getLogger(__name__)


# IPMonitoring system ----------------------------------------------------------------------
class IPMonitoringService:
    
    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')

         # লোকালহোস্ট চেক
        if ip in ('127.0.0.1', '::1'):
            ip = '127.0.0.1'
        
        return ip
    

    @staticmethod
    def get_device_info(request):
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')

        try:
            user_agent = parse(user_agent_string)

            device_type = 'other'
            if user_agent.is_mobile:
                device_type = 'mobile'
            elif user_agent.is_tablet:
                device_type = 'tablet'
            elif user_agent.is_pc:
                device_type = 'pc'
            elif user_agent.is_bot:
                device_type = 'bot'
            

            return{
                'device' : user_agent.device.family or 'Unknown',
                'device_type' : device_type,
                'browser' : user_agent.browser.family or 'Unknown',
                'browser_version': user_agent.browser.version_string or '',
                'os': user_agent.os.family or 'Unknown',
                'os_version': user_agent.os.version_string or '',
                'is_mobile': user_agent.is_mobile,
                'is_tablet': user_agent.is_tablet,
                'is_pc': user_agent.is_pc,
                'is_bot': user_agent.is_bot,
                'user_agent_string': user_agent_string[:500]

            }
            
        except Exception as e:
            logger.error(f"Error parsing user agent : {str(e)}")
            return{
                'device': 'Unknown',
                'device_type': 'other',
                'browser': 'Unknown',
                'browser_version': '',
                'os': 'Unknown',
                'os_version': '',
                'is_mobile': False,
                'is_tablet': False,
                'is_pc': False,
                'is_bot': False,
                'user_agent_string': user_agent_string[:500]
            }
        

    # IP Location Tracking ----------------------------------------------------------------
    @staticmethod
    def get_ip_location(ip_address):

        if ip_address in ('127.0.0.1', '::1'):
            return {

                'location' : 'Localhost',
                'latitude': None,
                'longitude': None,
                'city': 'Local',
                'country': 'Local'
            }
        
        try : 
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=3
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location_parts = []
                    if data.get('city'):
                        location_parts.append(data['city'])
                    if data.get('regionName'):
                        location_parts.append(data['regionName'])

                    if data.get('country'):
                        location_parts.append(data['country'])
                    
                    return {

                        'location': ', '.join(location_parts),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'city': data.get('city', ''),
                        'region': data.get('regionName', ''),
                        'country': data.get('country', ''),
                        'country_code': data.get('countryCode', ''),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', '')
                    }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting IP location : {str(e)}")

        return {

            'location' : 'Unknown',
            'latitude': None,
            'longitude': None,
            'city': '',
            'country': ''
        }
    
    @staticmethod
    def is_ip_allowed(user, ip_address):
        """
        IP অনুমোদিত কিনা চেক করা
        """

        if not user.is_ip_restricted:
            return True
        
        allowed_ips = user.get_allowed_ips_list()
        
        if ip_address in allowed_ips:
            return True
        
        whitelisted = IPWhitelist.objects.filter(
            user=user,
            ip_address = ip_address,
            is_active = True
        ).exists()
        return whitelisted
    

    @staticmethod
    def check_suspicious_activity(user, ip_address, device_info, request=None):
        """
        সন্দেহজনক অ্যাক্টিভিটি চেক করা
        """

        suspicious = False
        severity = 1
        activity_type = None
        details = {}

        recent_logins = LoginHistory.objects.filter(
            user=user,
            login_time__gte = timezone.now() - timedelta(hours=24)

        ) 

        # নতুন IP থেকে লগইন?

        if not recent_logins.filter(ip_address=ip_address).exists():
            Suspicious = True
            severity = 2
            activity_type = 'NEW_IP'
            details['message'] = 'নতুন IP ঠিকানা থেকে লগইন প্রচেষ্টা'

        last_login = LoginHistory.objects.filter(
            user = user,
            is_successful = True
        ).first()

        if last_login and last_login.device != device_info['device']:
            Suspicious = True
            severity = 2
            activity_type ='DEVICE_CHANGE'
            details['previous_device'] = last_login.device
            details['new_device'] = device_info['device']

        
        # অস্বাভাবিক সময়? (রাত ১১টা - সকাল ৫টা)
        current_hour = timezone.now().hour
        if current_hour < 5 or current_hour > 23:
            suspicious = True
            severity = 1
            activity_type = 'UNUSUAL_TIME'
            details['message'] = 'অস্বাভাবিক সময়ে লগইন প্রচেষ্টা'
        
        # দ্রুত অ্যাটেম্পট? (৫ মিনিটে ৫+ বার)
        rapid_attempts = LoginHistory.objects.filter(
            user=user,
            ip_address=ip_address,
            login_time__gte=timezone.now() - timedelta(minutes=5)
        ).count()
        
        if rapid_attempts > 5:
            suspicious = True
            severity = 3
            activity_type = 'RAPID_ATTEMPTS'
            details['attempts'] = rapid_attempts
        
        if suspicious and activity_type:
            # লোকেশন ইনফো
            location_info = IPMonitoringService.get_ip_location(ip_address)
            
            # সন্দেহজনক অ্যাক্টিভিটি তৈরি
            activity = SuspiciousActivity.objects.create(
                user=user,
                activity_type=activity_type,
                ip_address=ip_address,
                device=device_info['device'],
                browser=device_info['browser'],
                os=device_info['os'],
                location=location_info.get('location', 'Unknown'),
                details=details,
                severity=severity
            )
            
            # হাই সিভিরিটির জন্য অ্যালার্ট
            if severity >= 3:
                from .tasks import send_security_alert
                send_security_alert.delay(str(activity.id))
        
        return suspicious



# OTP -----------------------------
# security/services.py - OTPService অংশ

class OTPService:
    """
    OTP ম্যানেজমেন্ট সার্ভিস
    """
    
    @staticmethod
    def generate_otp(user):
        """
        OTP জেনারেট করা (৬ ডিজিট)
        """
        import pyotp
        totp = pyotp.TOTP(user.otp_secret, interval=300)  # 5 minutes
        return totp.now()
    
    @staticmethod
    def verify_otp(user, otp):
        """
        OTP ভেরিফাই করা
        """
        import pyotp
        totp = pyotp.TOTP(user.otp_secret, interval=300)
        return totp.verify(otp)
    
    @staticmethod
    def send_otp(user):
        """
        OTP জেনারেট এবং ইমেইলে পাঠানো (শুধু ইমেইল)
        """
        otp = OTPService.generate_otp(user)
        
        # Celery task কল (শুধু ইমেইল)
        from security.tasks import send_otp_email
        send_otp_email.delay(str(user.id), otp)
        
        return otp
    
    

class LoginHistoryService:
    """
    লগইন হিস্টোরি ম্যানেজমেন্ট সার্ভিস
    """

    @staticmethod
    def record_login(user, request, is_successful=True):
        ip_service = IPMonitoringService()
        
        ip_address = ip_service.get_client_ip(request)
        device_info = ip_service.get_device_info(request)
        location_info = ip_service.get_ip_location(ip_address)

        login_record = LoginHistory.objects.create(
            user=user,
            ip_address = ip_address,
            device = device_info['device'],
            browser=device_info['browser'],
            browser_version=device_info['browser_version'],
            os=device_info['os'],
            os_version=device_info['os_version'],
            device_type=device_info['device_type'],
            location=location_info.get('location', 'Unknown'),
            latitude=location_info.get('latitude'),
            longitude=location_info.get('longitude'),
            is_successful=is_successful,
            session_id=request.session.session_key or '',
            user_agent=device_info.get('user_agent_string', '')

        )

        if is_successful:
            user.last_login_ip = ip_address
            user.last_login_device = device_info['device']
            user.last_login_browser = device_info['browser']
            user.last_login_os = device_info['os']
            user.last_login_location = location_info.get('location', 'Unknown')
            user.last_login = timezone.now()
            user.save()
            
            # ব্যর্থ প্রচেষ্টা রিসেট
            user.reset_failed_attempts()
        
        return login_record
    


class SecurityAuditService:
    """
    সিকিউরিটি অডিট সার্ভিস
    """
    
    @staticmethod
    def log_event(user, event_type, request=None, ip_address=None, details=None):
        """
        সিকিউরিটি ইভেন্ট লগ করা
        """
        ip_service = IPMonitoringService()
        
        if request:
            ip_address = ip_address or ip_service.get_client_ip(request)
            device_info = ip_service.get_device_info(request)
            location_info = ip_service.get_ip_location(ip_address)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        else:
            device_info = {
                'device': 'Unknown',
                'browser': 'Unknown',
                'os': 'Unknown'
            }
            location_info = {'location': 'Unknown'}
            user_agent = ''
        
        # অডিট লগ তৈরি
        audit_log = SecurityAuditLog.objects.create(
            user=user,
            event_type=event_type,
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent,
            device=device_info['device'],
            browser=device_info['browser'],
            os=device_info['os'],
            location=location_info.get('location', 'Unknown'),
            details=details or {}
        )
        
        logger.info(
            f"Security event: {event_type} - User: {user.username} - IP: {ip_address}"
        )
        
        return audit_log


class TokenService:
    """
    টোকেন ম্যানেজমেন্ট সার্ভিস (JWT)
    """
    
    @staticmethod
    def generate_temp_token(user, ip_address):
        """
        টেম্পোরারি টোকেন জেনারেট (JWT)
        """
        import jwt
        from django.conf import settings
        from datetime import datetime, timedelta
        import uuid
        
        payload = {
            'user_id': str(user.id),
            'username': user.username,
            'email': user.email,
            'ip_address': ip_address,
            'requires_2fa': user.is_2fa_enabled,
            'exp': datetime.utcnow() + timedelta(minutes=5),
            'iat': datetime.utcnow(),
            'jti': str(uuid.uuid4())
        }
        
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        return token
    
    @staticmethod
    def verify_temp_token(token):
        """
        টেম্পোরারি টোকেন ভেরিফাই
        """
        import jwt
        from django.conf import settings
        
        try:
            payload = jwt.decode(
                token, 
                settings.SECRET_KEY, 
                algorithms=['HS256'],
                options={'verify_exp': True}
            )
            return payload, None
        except jwt.ExpiredSignatureError:
            return None, 'Token expired'
        except jwt.InvalidTokenError as e:
            return None, f'Invalid token: {str(e)}'