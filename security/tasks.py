from celery import shared_task
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
from security.models import SuspiciousActivity
from account.models import User
import logging

logger = logging.getLogger(__name__)


@shared_task
def send_otp_email(user_id, otp):
      
      """
    ইমেইলে OTP পাঠানো (শুধু ইমেইল)
    """
      try:
            user = User.objects.get(id=user_id)
            subject = f"Your OTP Code - {otp}"
            message = f"""
            Hello {user.username},

            Your One-Time Password (OTP) is : {otp}

            This code is valid for 5 minutes.
            please do not share this code with anyone.

            If you didn't request this, please ignore this email.
        
            Thank you,
            Your App Team
            """

            send_mail(
                  subject = subject,
                  message=message,
                  from_email='noreply@yourapp.com',
                  recipient_list=[user.email],
                  fail_silently=False,
            )

            logger.info(f'OTP email sent to {user.email}')
            return f"OTP email sent to {user.email}"
      
      except User.DoesNotExist:
            logger.error(f'User {user_id} not found for OTP email')
            return f"User {user_id} not found"
      
      except Exception as e:
            logger.error(f'Error sending OTP email: {str(e)}')
            return f'Error: {str(e)}'
      
            

@shared_task
def send_security_alert(activity_id):
    """
    সিকিউরিটি অ্যালার্ট পাঠানো
    """

    try:
          activity = SuspiciousActivity.objects.get(id=activity_id)

          admins = User.objects.filter(is_superuser=True, is_active=True)

          for admin in admins:
                subject = f"Security Alert: {activity.get_activity_type_display()}"
                message = f"""
                Security Alert

                User : {activity.user.username}
                Email : {activity.user.email}
                Activity: {activity.get_activity_type_display()}
                IP: {activity.ip_address}
                Device: {activity.device}
                Location: {activity.location}
                Severity: {activity.get_severity_display()}
                Time: {activity.created_at}
            
                Details: {activity.details}
                """


                send_mail(
                subject=subject,
                message=message,
                from_email='security@yourapp.com',
                recipient_list=[admin.email],
                fail_silently=True,
            )
          logger.info(f"Security alert sent for activity {activity_id}")
          return f"Alert sent for activity {activity_id}"
        
    except SuspiciousActivity.DoesNotExist:
        logger.error(f"Activity {activity_id} not found")
        return f"Activity {activity_id} not found"
    except Exception as e:
        logger.error(f"Error sending security alert: {str(e)}")
        return f"Error: {str(e)}"

      

@shared_task
def cleanup_old_records():
    """
    পুরনো রেকর্ড ক্লিনআপ (৯০ দিনের পুরনো)
    """
    from security.models import LoginHistory, SuspiciousActivity, SecurityAuditLog
    
    cutoff_date = timezone.now() - timedelta(days=90)
    
    # ৯০ দিনের পুরনো লগইন হিস্টোরি ডিলিট
    deleted_logins, _ = LoginHistory.objects.filter(
        login_time__lt=cutoff_date
    ).delete()
    
    # ৯০ দিনের পুরনো সন্দেহজনক অ্যাক্টিভিটি ডিলিট (রিজল্ভড)
    deleted_activities, _ = SuspiciousActivity.objects.filter(
        created_at__lt=cutoff_date,
        is_resolved=True
    ).delete()
    
    # ৯০ দিনের পুরনো অডিট লগ ডিলিট
    deleted_audit, _ = SecurityAuditLog.objects.filter(
        timestamp__lt=cutoff_date
    ).delete()
    
    result = {
        'deleted_logins': deleted_logins,
        'deleted_activities': deleted_activities,
        'deleted_audit': deleted_audit,
        'date': cutoff_date.strftime('%Y-%m-%d')
    }
    
    logger.info(f"Cleanup completed: {result}")
    return result



@shared_task
def check_suspicious_activities():
    """
    অমীমাংসিত সন্দেহজনক অ্যাক্টিভিটি চেক
    """
    from security.models import SuspiciousActivity
    
    # ২৪ ঘন্টার পুরনো অমীমাংসিত অ্যাক্টিভিটি
    unresolved = SuspiciousActivity.objects.filter(
        is_resolved=False,
        created_at__lte=timezone.now() - timedelta(hours=24)
    )
    
    count = 0
    for activity in unresolved:
        activity.is_resolved = True
        activity.resolution_note = "Auto-resolved after 24 hours"
        activity.save()
        count += 1
    
    logger.info(f"{count} activities auto-resolved")
    return f"{count} activities auto-resolved"



@shared_task
def send_daily_security_report():
    """
    দৈনিক সিকিউরিটি রিপোর্ট পাঠানো
    """
    from account.models import User
    from security.models import LoginHistory, SuspiciousActivity
    
    yesterday = timezone.now() - timedelta(days=1)
    
    # সুপারইউজারদের রিপোর্ট
    admins = User.objects.filter(is_superuser=True, is_active=True)
    
    for admin in admins:
        # গতকালের ডাটা
        logins = LoginHistory.objects.filter(
            user=admin,
            login_time__gte=yesterday
        )
        
        suspicious = SuspiciousActivity.objects.filter(
            user=admin,
            created_at__gte=yesterday
        )
        
        # রিপোর্ট তৈরি
        subject = f"Daily Security Report - {timezone.now().strftime('%Y-%m-%d')}"
        message = f"""
        Daily Security Report
        
        Date: {timezone.now().strftime('%Y-%m-%d')}
        
        Login Summary:
        - Total Logins: {logins.count()}
        - Successful: {logins.filter(is_successful=True).count()}
        - Failed: {logins.filter(is_successful=False).count()}
        
        Security Alerts:
        - Total Suspicious Activities: {suspicious.count()}
        - Unresolved: {suspicious.filter(is_resolved=False).count()}
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email='reports@yourapp.com',
            recipient_list=[admin.email],
            fail_silently=True,
        )
    
    return f"Daily reports sent to {admins.count()} admins"




@shared_task
def send_welcome_email(user_id):
    """
    নতুন ইউজারকে ওয়েলকাম ইমেইল
    """
    from account.models import User
    
    try:
        user = User.objects.get(id=user_id)
        
        subject = f"Welcome to Our App, {user.username}!"
        message = f"""
        Welcome {user.username}!
        
        Thank you for registering with us.
        
        Your account has been created successfully.
        You can now login using your email: {user.email}
        
        Best regards,
        Your App Team
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email='welcome@yourapp.com',
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        logger.info(f"Welcome email sent to {user.email}")
        return f"Welcome email sent to {user.email}"
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found")
        return f"User {user_id} not found"
    except Exception as e:
        logger.error(f"Error sending welcome email: {str(e)}")
        return f"Error: {str(e)}"


@shared_task
def send_password_reset_email(user_id, reset_link):
    """
    পাসওয়ার্ড রিসেট ইমেইল
    """
    from account.models import User
    
    try:
        user = User.objects.get(id=user_id)
        
        subject = "Password Reset Request"
        message = f"""
        Hello {user.username},
        
        You requested to reset your password.
        
        Click the link below to reset your password:
        {reset_link}
        
        This link is valid for 1 hour.
        
        If you didn't request this, please ignore this email.
        
        Thank you,
        Your App Team
        """
        
        send_mail(
            subject=subject,
            message=message,
            from_email='security@yourapp.com',
            recipient_list=[user.email],
            fail_silently=False,
        )
        
        logger.info(f"Password reset email sent to {user.email}")
        return f"Password reset email sent to {user.email}"
        
    except User.DoesNotExist:
        logger.error(f"User {user_id} not found")
        return f"User {user_id} not found"
    except Exception as e:
        logger.error(f"Error sending password reset email: {str(e)}")
        return f"Error: {str(e)}"