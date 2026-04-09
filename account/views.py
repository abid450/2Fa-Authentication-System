from rest_framework import status, generics, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from django.db.models import Q
from datetime import timedelta
import jwt
from django.conf import settings
import pyotp
import uuid
from .models import User
from .serializers import *
from security.service import *
from utils.pagination import *
from security.models import *
from security.permissoin import *
from security.throttling import *
from security.serializers import *
from utils.cache import LoginAttemptCache, OTPCache, TempTokenCache, RateLimiter

import logging
logger = logging.getLogger(__name__)



# ====================== বেস ভিউ ======================

class BaseAPIView(APIView):
    """
    বেস API ভিউ - সব ভিউ এই ক্লাস এক্সটেন্ড করবে
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_service = IPMonitoringService()
        self.login_attempt_cache = LoginAttemptCache()
        self.otp_cache = OTPCache()
        self.temp_token_cache = TempTokenCache()
        self.rate_limiter = RateLimiter()
    
    def get_client_ip(self, request):
        return self.ip_service.get_client_ip(request)
    
    def get_device_info(self, request):
        return self.ip_service.get_device_info(request)
    
    def log_security_event(self, user, event_type, request, details=None):
        SecurityAuditService.log_event(
            user=user,
            event_type=event_type,
            request=request,
            details=details or {}
        )


# ====================== অথেনটিকেশন ভিউ ======================

class UserRegistrationView(BaseAPIView, generics.CreateAPIView):
    """
    ইউজার রেজিস্ট্রেশন API
    POST /api/accounts/register/
    """
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    throttle_classes = [RegistrationThrottle]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # IP এবং ডিভাইস ইনফো সেভ
            ip = self.get_client_ip(request)
            device_info = self.get_device_info(request)
            location_info = self.ip_service.get_ip_location(ip)
            
            user.last_login_ip = ip
            user.last_login_device = device_info.get('device')
            user.last_login_browser = device_info.get('browser')
            user.last_login_os = device_info.get('os')
            user.last_login_location = location_info.get('location', 'Unknown')
            user.save()
            
            # ওয়েলকাম ইমেইল পাঠান (Celery task)
            from security.tasks import send_welcome_email
            send_welcome_email.delay(str(user.id))
            
            # সিকিউরিটি ইভেন্ট লগ
            self.log_security_event(
                user=user,
                event_type='USER_REGISTERED',
                request=request,
                details={'registration_method': 'email'}
            )
            
            return Response({
                'status': 'success',
                'message': 'রেজিস্ট্রেশন সফল হয়েছে',
                'data': {
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.get_full_name()
                }
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'status': 'error',
            'message': 'রেজিস্ট্রেশন ব্যর্থ হয়েছে',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(BaseAPIView):
    """
    লগইন API (প্রথম ধাপ)
    POST /api/accounts/login/
    """
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'status': 'error',
                'message': 'ইনপুট ডাটা সঠিক নয়',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.validated_data['user']
        ip_address = self.get_client_ip(request)
        device_info = self.get_device_info(request)
        
        # ব্যর্থ প্রচেষ্টা রিসেট (সফল হলে)
        self.login_attempt_cache.reset_failed_attempts(user.email, ip_address)
        
        # IP রেস্ট্রিকশন চেক
        if not self.ip_service.is_ip_allowed(user, ip_address):
            SuspiciousActivity.objects.create(
                user=user,
                activity_type='IP_CHANGE',
                ip_address=ip_address,
                device=device_info['device'],
                details={'message': 'অননুমোদিত IP থেকে লগইন প্রচেষ্টা'},
                severity=2
            )
            
            self.log_security_event(
                user=user,
                event_type='LOGIN_FAILED',
                request=request,
                details={'reason': 'ip_not_allowed'}
            )
            
            return Response({
                'status': 'error',
                'message': 'এই IP ঠিকানা থেকে লগইন অনুমোদিত নয়'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # সন্দেহজনক অ্যাক্টিভিটি চেক
        is_suspicious = self.ip_service.check_suspicious_activity(
            user, ip_address, device_info, request
        )
        
        # টেম্পোরারি টোকেন জেনারেট
        temp_token = TokenService.generate_temp_token(user, ip_address)
        self.temp_token_cache.store_token(str(user.id), temp_token)
        
        # লগইন অ্যাটেম্পট লগ
        LoginHistoryService.record_login(user, request, is_successful=False)
        
        # 2FA চেক
        if user.is_2fa_enabled:
            # OTP জেনারেট ও পাঠান
            otp = OTPService.send_otp(user)
            self.otp_cache.store_otp(str(user.id), otp)
            
            self.log_security_event(
                user=user,
                event_type='LOGIN_SUCCESS',
                request=request,
                details={'stage': 'credentials_verified', '2fa_required': True}
            )
            
            return Response({
                'status': 'success',
                'message': 'লগইন সফল হয়েছে। OTP ভেরিফিকেশন প্রয়োজন।',
                'data': {
                    'requires_2fa': True,
                    'temp_token': temp_token,
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'is_suspicious': is_suspicious
                }
            })
        
        # সরাসরি লগইন (2FA ছাড়া)
        refresh = RefreshToken.for_user(user)
        
        # লগইন সফল হিসেবে আপডেট
        LoginHistory.objects.filter(
            user=user,
            ip_address=ip_address,
            is_successful=False
        ).update(is_successful=True)
        
        # ইউজার ইনফো আপডেট
        user.last_login = timezone.now()
        user.last_login_ip = ip_address
        user.last_login_device = device_info.get('device')
        user.save()
        
        self.log_security_event(
            user=user,
            event_type='LOGIN_SUCCESS',
            request=request,
            details={'stage': 'complete', '2fa_required': False}
        )
        
        return Response({
            'status': 'success',
            'message': 'লগইন সফল হয়েছে',
            'data': {
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.get_full_name(),
                    'is_2fa_enabled': user.is_2fa_enabled
                },
                'is_suspicious': is_suspicious
            }
        })


class OTPVerificationView(BaseAPIView):
    """
    OTP ভেরিফিকেশন API (দ্বিতীয় ধাপ)
    POST /api/accounts/verify-otp/
    """
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]
    
    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'status': 'error',
                'message': 'ইনপুট ডাটা সঠিক নয়',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # টেম্পোরারি টোকেন ভেরিফাই
        payload, error = TokenService.verify_temp_token(serializer.validated_data['temp_token'])
        if error:
            return Response({
                'status': 'error',
                'message': error
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=payload['user_id'])
            ip_address = self.get_client_ip(request)
            
            # IP ম্যাচ চেক
            if payload.get('ip_address') != ip_address:
                SuspiciousActivity.objects.create(
                    user=user,
                    activity_type='IP_CHANGE',
                    ip_address=ip_address,
                    details={
                        'message': 'OTP ভেরিফিকেশনের সময় IP পরিবর্তন হয়েছে',
                        'expected_ip': payload.get('ip_address')
                    },
                    severity=2
                )
                
                return Response({
                    'status': 'error',
                    'message': 'আপনার IP ঠিকানা পরিবর্তন হয়েছে। আবার লগইন করুন।'
                }, status=status.HTTP_403_FORBIDDEN)
            
            # OTP ভেরিফাই
            otp_valid = self.otp_cache.verify_otp(
                str(user.id), 
                serializer.validated_data['otp']
            )
            
            if not otp_valid:
                # ব্যর্থ OTP প্রচেষ্টা ট্র্যাক
                failed_count = self.otp_cache.increment_failed_attempts(str(user.id))
                
                if failed_count >= 3:
                    SuspiciousActivity.objects.create(
                        user=user,
                        activity_type='MULTIPLE_FAILED',
                        ip_address=ip_address,
                        details={'attempts': failed_count, 'type': 'otp_failed'},
                        severity=2
                    )
                
                return Response({
                    'status': 'error',
                    'message': 'OTP সঠিক নয় বা মেয়াদ উত্তীর্ণ হয়েছে'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # ব্যর্থ প্রচেষ্টা রিসেট
            self.otp_cache.reset_failed_attempts(str(user.id))
            
            # ফাইনাল টোকেন জেনারেট
            refresh = RefreshToken.for_user(user)
            
            # লগইন হিস্টোরি আপডেট
            device_info = self.get_device_info(request)
            location_info = self.ip_service.get_ip_location(ip_address)
            
            LoginHistory.objects.filter(
                user=user,
                ip_address=ip_address,
                is_successful=False
            ).update(
                is_successful=True,
                device=device_info.get('device'),
                browser=device_info.get('browser'),
                os=device_info.get('os'),
                location=location_info.get('location', 'Unknown')
            )
            
            # ইউজার ইনফো আপডেট
            user.last_login = timezone.now()
            user.last_login_ip = ip_address
            user.last_login_device = device_info.get('device')
            user.last_login_browser = device_info.get('browser')
            user.last_login_os = device_info.get('os')
            user.last_login_location = location_info.get('location', 'Unknown')
            user.save()
            
            self.log_security_event(
                user=user,
                event_type='LOGIN_SUCCESS',
                request=request,
                details={'stage': 'otp_verified', 'method': '2fa'}
            )
            
            return Response({
                'status': 'success',
                'message': 'OTP ভেরিফিকেশন সফল হয়েছে',
                'data': {
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'full_name': user.get_full_name(),
                        'is_2fa_enabled': user.is_2fa_enabled
                    }
                }
            })
            
        except User.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'ইউজার পাওয়া যায়নি'
            }, status=status.HTTP_404_NOT_FOUND)


class TokenRefreshView(APIView):
    """
    টোকেন রিফ্রেশ API
    POST /api/accounts/token/refresh/
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response({
                'status': 'error',
                'message': 'রিফ্রেশ টোকেন প্রয়োজন'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            return Response({
                'status': 'success',
                'data': {
                    'access_token': access_token
                }
            })
        except Exception as e:
            return Response({
                'status': 'error',
                'message': 'ইনভ্যালিড রিফ্রেশ টোকেন'
            }, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    """
    লগআউট API
    POST /api/accounts/logout/
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # লগআউট টাইম আপডেট
            LoginHistory.objects.filter(
                user=request.user,
                session_id=request.session.session_key,
                logout_time__isnull=True
            ).update(logout_time=timezone.now())
            
            SecurityAuditService.log_event(
                user=request.user,
                event_type='LOGOUT',
                request=request
            )
            
            return Response({
                'status': 'success',
                'message': 'লগআউট সফল হয়েছে'
            })
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'লগআউট ব্যর্থ হয়েছে'
            }, status=status.HTTP_400_BAD_REQUEST)


# ====================== প্রোফাইল ভিউসেট ======================



# ====================== 2FA ভিউসেট ======================

class TwoFactorViewSet(viewsets.ViewSet, BaseAPIView):
    """
    2FA ম্যানেজমেন্ট ভিউসেট
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def status(self, request):
        """2FA স্ট্যাটাস দেখা"""
        user = request.user
        
        if user.is_2fa_enabled:
            return Response({
                'status': 'success',
                'data': {
                    'is_2fa_enabled': True,
                    'enabled_at': user.two_factor_enabled_at
                }
            })
        else:
            # QR কোড জেনারেট
            totp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(
                name=user.email,
                issuer_name="2FA System"
            )
            
            return Response({
                'status': 'success',
                'data': {
                    'is_2fa_enabled': False,
                    'secret': user.otp_secret,
                    'qr_code_uri': totp_uri,
                    'setup_instructions': {
                        'google_authenticator': 'Google Authenticator অ্যাপে QR কোড স্ক্যান করুন',
                        'manual': f'সিক্রেট কী: {user.otp_secret}'
                    }
                }
            })
    
    @action(detail=False, methods=['post'])
    def enable(self, request):
        """2FA সক্রিয় করা"""
        user = request.user
        
        if user.is_2fa_enabled:
            return Response({
                'status': 'error',
                'message': '2FA ইতিমধ্যে সক্রিয় আছে'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = TwoFactorEnableSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'status': 'error',
                'message': 'ইনপুট ডাটা সঠিক নয়',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # OTP ভেরিফাই
        if not user.verify_otp(serializer.validated_data['otp']):
            return Response({
                'status': 'error',
                'message': 'OTP সঠিক নয়'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # 2FA সক্রিয়
        user.is_2fa_enabled = True
        user.two_factor_enabled_at = timezone.now()
        user.save()
        
        self.log_security_event(
            user=user,
            event_type='2FA_ENABLED',
            request=request
        )
        
        return Response({
            'status': 'success',
            'message': '2FA সফলভাবে সক্রিয় করা হয়েছে'
        })
    
    @action(detail=False, methods=['post'])
    def disable(self, request):
        """2FA নিষ্ক্রিয় করা"""
        user = request.user
        
        if not user.is_2fa_enabled:
            return Response({
                'status': 'error',
                'message': '2FA সক্রিয় নেই'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # পাসওয়ার্ড ভেরিফিকেশন
        password = request.data.get('password')
        if not user.check_password(password):
            return Response({
                'status': 'error',
                'message': 'পাসওয়ার্ড সঠিক নয়'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # 2FA নিষ্ক্রিয়
        user.is_2fa_enabled = False
        user.two_factor_enabled_at = None
        user.otp_secret = pyotp.random_base32()  # নতুন সিক্রেট
        user.save()
        
        self.log_security_event(
            user=user,
            event_type='2FA_DISABLED',
            request=request,
            details={'reason': 'user_requested'}
        )
        
        return Response({
            'status': 'success',
            'message': '2FA নিষ্ক্রিয় করা হয়েছে'
        })


# ====================== IP হোয়াইটলিস্ট ভিউসেট ======================

class IPWhitelistViewSet(viewsets.ModelViewSet, BaseAPIView):
    """
    IP হোয়াইটলিস্ট ম্যানেজমেন্ট
    """
    serializer_class = IPWhitelistSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultSetPagination
    
    def get_queryset(self):
        return IPWhitelist.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        ip_address = serializer.validated_data.get('ip_address')
        
        # IP ভ্যালিডেশন
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise serializers.ValidationError('ইনভ্যালিড IP অ্যাড্রেস')
        
        serializer.save(user=self.request.user)
        
        self.log_security_event(
            user=self.request.user,
            event_type='IP_WHITELIST_ADD',
            request=self.request,
            details={'ip': ip_address}
        )


# ====================== লগইন হিস্টোরি ভিউসেট ======================

class LoginHistoryViewSet(viewsets.ReadOnlyModelViewSet, BaseAPIView):
    """
    লগইন হিস্টোরি দেখা
    """
    serializer_class = LoginHistorySerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    pagination_class = StandardResultSetPagination
    
    def get_queryset(self):
        user = self.request.user
        
        if user.is_staff or user.is_superuser:
            # অ্যাডমিন সব লগ দেখতে পারে
            return LoginHistory.objects.all()
        else:
            # সাধারণ ইউজার শুধু নিজের লগ দেখতে পারে
            return LoginHistory.objects.filter(user=user)
    
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """লগইন সামারি"""
        queryset = self.get_queryset()
        
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        
        summary = {
            'total_logins': queryset.count(),
            'successful_logins': queryset.filter(is_successful=True).count(),
            'failed_logins': queryset.filter(is_successful=False).count(),
            'unique_ips': queryset.values('ip_address').distinct().count(),
            'unique_devices': queryset.values('device').distinct().count(),
            'last_24h': queryset.filter(login_time__gte=last_24h).count(),
            'last_24h_successful': queryset.filter(login_time__gte=last_24h, is_successful=True).count(),
            'last_24h_failed': queryset.filter(login_time__gte=last_24h, is_successful=False).count(),
        }
        
        return Response({
            'status': 'success',
            'data': summary
        })


# ====================== সন্দেহজনক অ্যাক্টিভিটি ভিউসেট ======================

class SuspiciousActivityViewSet(viewsets.ReadOnlyModelViewSet, BaseAPIView):
    """
    সন্দেহজনক অ্যাক্টিভিটি দেখা
    """
    serializer_class = SuspiciousActivitySerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    pagination_class = StandardResultSetPagination
    
    def get_queryset(self):
        user = self.request.user
        
        if user.is_staff or user.is_superuser:
            return SuspiciousActivity.objects.all()
        else:
            return SuspiciousActivity.objects.filter(user=user)
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """অ্যাক্টিভিটি রিজল্ভ করা"""
        activity = self.get_object()
        
        if activity.user != request.user and not request.user.is_staff:
            return Response({
                'status': 'error',
                'message': 'এই অ্যাক্টিভিটি রিজল্ভ করার অনুমতি নেই'
            }, status=status.HTTP_403_FORBIDDEN)
        
        activity.is_resolved = True
        activity.resolved_at = timezone.now()
        activity.resolution_note = request.data.get('note', '')
        activity.save()
        
        return Response({
            'status': 'success',
            'message': 'অ্যাক্টিভিটি রিজল্ভ করা হয়েছে'
        })


# ====================== অডিট লগ ভিউসেট (শুধু অ্যাডমিন) ======================

class SecurityAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    সিকিউরিটি অডিট লগ (শুধু অ্যাডমিন)
    """
    serializer_class = SecurityAuditLogSerializer
    permission_classes = [IsAuthenticated, IsAdminOnly]
    pagination_class = StandardResultSetPagination
    queryset = SecurityAuditLog.objects.all().order_by('-timestamp')
    filterset_fields = ['event_type', 'user']
    search_fields = ['ip_address', 'location', 'details']