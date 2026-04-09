import re
import ipaddress
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import datetime

def validate_bangladesh_phone(phone):
    """
    বাংলাদেশী মোবাইল নম্বর ভ্যালিডেশন
    ফরম্যাট: 01XXXXXXXXX (মোট ১১ ডিজিট)
    """
    # শুধু ডিজিট রাখা
    phone = re.sub(r'\D', '', phone)
    
    # বাংলাদেশী ফোন নম্বর প্যাটার্ন
    pattern = r'^01[3-9]\d{8}$'  # 013-019 পর্যন্ত
    
    if not re.match(pattern, phone):
        raise ValidationError(
            _('%(phone)s সঠিক বাংলাদেশী ফোন নম্বর নয়। ফরম্যাট: 01XXXXXXXXX (১১ ডিজিট)'),
            params={'phone': phone},
        )
    
    return phone


def validate_ip_address(ip):
    """
    IP অ্যাড্রেস ভ্যালিডেশন (IPv4 এবং IPv6)
    """
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValidationError(
            _('%(ip)s সঠিক IP অ্যাড্রেস নয়'),
            params={'ip': ip},
        )


def validate_ipv4_address(ip):
    """
    শুধু IPv4 অ্যাড্রেস ভ্যালিডেশন
    """
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        raise ValidationError(
            _('%(ip)s সঠিক IPv4 অ্যাড্রেস নয়'),
            params={'ip': ip},
        )


def validate_ipv6_address(ip):
    """
    শুধু IPv6 অ্যাড্রেস ভ্যালিডেশন
    """
    try:
        ipaddress.IPv6Address(ip)
        return ip
    except ValueError:
        raise ValidationError(
            _('%(ip)s সঠিক IPv6 অ্যাড্রেস নয়'),
            params={'ip': ip},
        )


def validate_password_strength(password):
    """
    পাসওয়ার্ড স্ট্রেংথ চেক
    """
    errors = []
    
    if len(password) < 8:
        errors.append("পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে")
    
    if not re.search(r'[A-Z]', password):
        errors.append("পাসওয়ার্ডে কমপক্ষে একটি বড় হাতের অক্ষর থাকতে হবে (A-Z)")
    
    if not re.search(r'[a-z]', password):
        errors.append("পাসওয়ার্ডে কমপক্ষে একটি ছোট হাতের অক্ষর থাকতে হবে (a-z)")
    
    if not re.search(r'[0-9]', password):
        errors.append("পাসওয়ার্ডে কমপক্ষে একটি সংখ্যা থাকতে হবে (0-9)")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("পাসওয়ার্ডে কমপক্ষে একটি বিশেষ অক্ষর থাকতে হবে (!@#$%^&* etc)")
    
    if errors:
        raise ValidationError(errors)
    
    return password