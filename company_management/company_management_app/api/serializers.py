from rest_framework import serializers
from company_management_app.models import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed

''' UserSerializer used for displaying data of user '''

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name','last_name', 'phone', 'email', 'password', 'role', 'is_active']
        extra_kwargs = {'email': {'read_only': True}, 'password': {'read_only': True}}

''' RegisterSerializer used for registering new user '''

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField( write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['id', 'first_name','last_name', 'phone', 'email', 'role', 'password']

    def validate(self, attrs):
        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

''' LoginSerializer user can login to the system and gives refresh token and access token '''

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 255, min_length = 3)
    password = serializers.CharField(max_length = 16, min_length = 6, write_only = True,  style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ['email', 'password']

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password')

        user = authenticate(email=email, password=password)

        if not user:
            raise serializers.ValidationError('This email or password is wrong.')
        
        user_is_active = User.objects.filter(email = email).first()

        if not user_is_active.is_active:
            raise serializers.ValidationError('Your account is disabled please contact your admin.')

        data['user'] = user
        return data

''' VerifyOtpSerializer user can submit otp for verify phone number authentication '''

class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 255, min_length = 3)
    email_otp = serializers.CharField(allow_blank=True)

''' LogoutSerializer user can logout from the system using refresh token '''

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        
        except TokenError:
            self.fail('bad request')

''' CompanySerializer and UpdateCompanySerializer can serializes the data for adding and updating company by Super Admin '''

class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'
        extra_kwargs = {'is_active': {'read_only': True}}

class UpdateCompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = '__all__'

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ['id', 'company_id', 'first_name', 'last_name', 'phone', 'email', 'role', 'password', 'is_active']

    def validate(self, attrs):
        return super().validate(attrs)

    def create(self, validated_data):
        return Customer.objects.create_user(**validated_data)

''' Change Password Serializer '''
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username','old_password', 'new_password','confirm_password']

    def update(self, instance, validated_data):
        instance.password = validated_data.get('password', instance.password)

        if not validated_data['new_password']:
                raise serializers.ValidationError({'new_password': 'not found'})

        if not validated_data['old_password']:
                raise serializers.ValidationError({'old_password': 'not found'})

        if not instance.check_password(validated_data['old_password']):
                raise serializers.ValidationError({'old_password': 'wrong password'})

        if validated_data['new_password'] != validated_data['confirm_password']:
            raise serializers.ValidationError({'passwords': 'passwords do not match'})

        if validated_data['old_password'] == validated_data['new_password']:
            raise serializers.ValidationError({'passwords': 'old password is same as new password'})
        
        if validated_data['new_password'] == validated_data['confirm_password'] and instance.check_password(validated_data['old_password']):
            instance.set_password(validated_data['new_password'])
            instance.save()
            return instance
        return instance

# Password Reset Serializer class

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2,required=True)
    class Meta:
        fields = ['email']
        
        
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)
    
    class Meta:
        fields = ['password', 'token', 'uidb64']
        
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            uuid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uuid)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed('The reset link is invalid',401)
            user.set_password(password)
            user.save()
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid',401) from e
        return super().validate(attrs)