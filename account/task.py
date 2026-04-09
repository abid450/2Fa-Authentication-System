from celery import shared_task
from django.core.mail import send_mail

@shared_task
def send_otp_email(email, otp):
    send_mail(
        subject="Your OTP Code",
        message=f"Your OTP is: {otp}",
        from_email="noreply@company.com",
        recipient_list=[email],
        fail_silently=False
    )
