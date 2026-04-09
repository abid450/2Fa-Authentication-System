import random
from django.utils import timezone
from datetime import timedelta


def generate_otp():
    return str(random.randint(100000, 999999))


def otp_expiry(minutes=5):
    return timezone.now() + timedelta(minutes=minutes)
