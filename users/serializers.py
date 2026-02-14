
from .models import HostProfile, User

from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str,force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.conf import settings
from django.core.mail import send_mail


from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

# Register
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ["username", "email", "password", "password2"]

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")

        user = User.objects.create_user(**validated_data)
        user.is_verified = False
        user.save(update_fields=["is_verified"])

        # 🔐 Generate token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        print(uid)
        print(token)
        verify_link = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}"

        html_content = render_to_string(
            "emails/verify_email.html",
            {"verify_link": verify_link}
        )

        email = EmailMultiAlternatives(
            subject="Verify your account",
            body="Please verify your email",
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )

        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=False)

        return user


#Login
class EmailTokenObtainSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        user = authenticate(request=self.context.get('request'), username=email, password=password)

        if not user:
            raise serializers.ValidationError({
                "detail": "Invalid email or password"
            })

        if not user.is_verified:
            raise serializers.ValidationError({
                "detail": "Please verify your email before logging in"
            })

        refresh = RefreshToken.for_user(user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

#Logout
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs.get("refresh")
        if not self.token:
            raise ValidationError({"refresh": "Refresh token is required"})
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            raise ValidationError({"detail": "Invalid or expired token"})

#Serializer de resetear password
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

#Serializer de Confirmar reset password
class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    password = serializers.CharField(write_only=True, validators=[validate_password])

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs["uid"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uid": "Invalid user ID"})

        if not default_token_generator.check_token(user, attrs["token"]):
            raise serializers.ValidationError({"token": "Invalid or expired token"})

        attrs["user"] = user
        return attrs

    def save(self):
        user = self.validated_data["user"]
        password = self.validated_data["password"]

        user.set_password(password)
        user.save()

        return user


class ChangePasswordSerializer(serializers.Serializer):

    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password]
    )
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError(
                {"new_password": "Passwords do not match"}
            )
        return attrs


#Confirmar cuenta correo al email
class EmailVerificationSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs["uid"]))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uid": "Invalid user"})

        if not default_token_generator.check_token(user, attrs["token"]):
            raise serializers.ValidationError({"token": "Invalid or expired token"})

        attrs["user"] = user
        return attrs

    def save(self):
        user = self.validated_data["user"]
        user.is_verified = True
        user.save()
        return user

#Serializer de respuesta de endpoint de token
class TokenResponseSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()


#Serializer de HOST
class HostProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostProfile
        fields = [
            "is_host",
            "description",
            "phone",
            "months_hosting",
            "profession",
            "rating",
            "total_reviews",
        ]
        read_only_fields = [
            "is_host",
            "months_hosting",
            "rating",
            "total_reviews",
        ]

#Serializer de usuario común
class UserSerializer(serializers.ModelSerializer):
    host_profile = HostProfileSerializer(read_only=True)
    is_host = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "phone",
            "profile_image",
            "is_host",
            "host_profile",
        ]

    def get_is_host(self, obj) -> bool:
        return obj.host_profile.is_host


#Base de user
class BaseUserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "phone"]


#Serializers endpoint usuario host
class HostActivationSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostProfile
        fields = ["description", "phone", "profession"]


class BaseResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    message = serializers.CharField(required=False, allow_blank=True, default="")

class DataResponseSerializer(BaseResponseSerializer):
    data = serializers.JSONField(required=False)


class UserResponseSerializer(BaseResponseSerializer):
    data = UserSerializer()

class HostResponseSerializer(BaseResponseSerializer):
    data = HostActivationSerializer(required=False)

class ErrorResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField(default=False)
    errors = serializers.JSONField()
    status_code = serializers.IntegerField()