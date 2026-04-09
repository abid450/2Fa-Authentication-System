"""
URL configuration for chat project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from account.views import *
from rest_framework.routers import DefaultRouter
from account.views import *

router = DefaultRouter()
router.register(r'ip-whitelist', IPWhitelistViewSet, basename='ip-whitelist')
router.register(r'login-history', LoginHistoryViewSet, basename='login-history')
router.register(r'suspicious-activities', SuspiciousActivityViewSet, basename='suspicious-activities')
router.register(r'audit-logs', SecurityAuditLogViewSet, basename='audit-logs')
router.register(r'2fa', TwoFactorViewSet, basename='2fa')


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('login/', LoginView.as_view(), name='login'),
    path('register', UserRegistrationView.as_view(), name='register'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),




   

    
]
