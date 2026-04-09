from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from .models import *
import re


class UserRegistrationSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password],
        style={'input_type': 'Password'},
        error_messages = {'required': 'পাসওয়ার্ড দিতে হবে',}
    )

    password2 = serializers.CharField(
        write_only=True, 
        required=True,
        label = 'Confirm Password',
        style={'input_type': 'Password'},
        error_messages = {'required': 'কনফার্ম পাসওয়ার্ড দিতে হবে',}
    )
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'phone', 'password', 'password2',
        ]


    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError('এই ইউজারনেম ইতিমধ্যে ব্যবহার হচ্ছে')
        
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                "ইউজারনেম শুধু অক্ষর, সংখ্যা এবং আন্ডারস্কোর থাকতে পারে"
            )
        return value
    

    def validate_email(self, email):
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError('ইমেইল ইতিমধ্যে ব্যবহার হচ্ছে')
        return email
    

    def validate_phone(self, value):
        if User.objects.filter(phone=value).exists():
            raise serializers.ValidationError('ফোন নম্বর ইতিমধ্যে ব্যবহার হচ্ছে')
        
           # বাংলাদেশী ফোন নম্বর ফরম্যাট চেক (সহজ ভার্সন)
        if not re.match(r'^01[3-9]\d{8}$', value):
            raise serializers.ValidationError(
                "সঠিক ফোন নম্বর দিন (যেমন: 017xxxxxxxx)"
            )
        
        return value
    

    def validate(self, attrs):

        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password and password2 and password != password2:
            raise serializers.ValidationError({
                'password': 'পাসওয়ার্ড দুটি মিলছে না',
                'password2': 'পাসওয়ার্ড দুটি মিলছে না'

            })
        
        return attrs
    
    
    def create(self, validate_data):
        validate_data.pop('password2')
        user = User.objects.create_user(
            username = validate_data['username'],
            email = validate_data['email'],
            phone = validate_data['phone'],
            password = validate_data['password']
        )
        return user
    


class UserSerializer(serializers.ModelSerializer):
    """
    ইউজার ডিটেইলস দেখানোর সিরিয়ালাইজার
    """
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'phone', 'first_name', 'last_name',
            'full_name', 'is_2fa_enabled', 'last_login', 'last_login_ip',
            'last_login_device', 'last_login_location', 'is_ip_restricted',
            'is_locked', 'created_at'
        ]
        read_only_fields = ['id', 'last_login', 'created_at']
    
    def get_full_name(self, obj):
        return obj.get_full_name()

    
# Login -------------------------------------------------------------------
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type' : 'password'})

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("ইমেইল এবং পাসওয়ার্ড দিন")
        

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                'ইমেইল বা পাসওয়ার্ড সঠিক নয়'
            )
        
        # পাসওয়ার্ড চেক
        if not user.check_password(password):
            # ব্যর্থ প্রচেষ্টা ইনক্রিমেন্ট
            user.increment_failed_attempts()
            raise serializers.ValidationError(
                "ইমেইল বা পাসওয়ার্ড সঠিক নয়"
            )
        
        # অ্যাকাউন্ট সক্রিয় কিনা চেক
        if not user.is_active:
            raise serializers.ValidationError(
                "এই অ্যাকাউন্টটি সক্রিয় নয়"
            )
        

          # অ্যাকাউন্ট লকড কিনা চেক
        if user.is_locked:
            from django.utils import timezone
            if user.locked_until and user.locked_until > timezone.now():
                remaining = (user.locked_until - timezone.now()).seconds // 60
                raise serializers.ValidationError(
                    f'অ্যাকাউন্ট লক করা আছে। {remaining} মিনিট পর আবার চেষ্টা করুন'
                )
            else:
                user.is_locked = False
                user.locked_until = None
                user.save()
        
        data['user'] = user
        return data



# OTP ---------------------------------------------------------------
class OTPVerifySerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=True)
    otp = serializers.CharField(max_length=6, min_length=6, required=True)
    temp_token = serializers.CharField(required=True)


    def validate_otp(self, value):
        if not value.isdigit():
             raise serializers.ValidationError("OTP শুধু সংখ্যা হতে হবে")
        return value
    


#2 Fa ------------------------------------------------------------------

class TwoFactorEnableSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6, required=True)
    
    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP শুধু সংখ্যা হতে হবে")
        return value


    


# IpWhite -----------------------------------------------------------------
class IPWhitelistSerializer(serializers.Serializer):
    ip_address = serializers.CharField(required=True)
    description = serializers.CharField(required=False, allow_blank=True)
    
    def validate_ip_address(self, value):
        import ipaddress
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError("সঠিক IP অ্যাড্রেস দিন")
        return value