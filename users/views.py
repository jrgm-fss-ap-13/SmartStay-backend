from .serializers import *

from django.contrib.auth import get_user_model

from users.throttles import LoginRateThrottle, PasswordResetRateThrottle
from .models import HostProfile, User

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication


from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from drf_spectacular.utils import extend_schema,extend_schema_view,OpenApiResponse

from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode

from django.conf import settings
from django.utils.encoding import force_bytes

User = get_user_model()

@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        request=TokenRefreshSerializer,
        responses={
            200: TokenRefreshSerializer,
            401: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Invalid or expired refresh token."
            ),
        },
        auth=[],
        description="Get a new access token using a refresh token.",
    )
)
class CustomTokenRefreshView(TokenRefreshView):
    """
    Takes a refresh token and returns a new access token.
    """
    pass

class RegisterView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=RegisterSerializer,
        responses={
            201: BaseResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Validation error. Email may already exist or data is invalid."
            ),
        },
        tags=["Auth"],
        auth=[]
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "User registered successfully"},
            status=status.HTTP_201_CREATED,
        )

class EmailLoginView(APIView):
    throttle_classes = [LoginRateThrottle]
    permission_classes = [AllowAny]

    @extend_schema(
        request=EmailTokenObtainSerializer,
        responses={
            200: TokenResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Invalid email or password."
            ),
            429: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too many login attempts. Try again later."
            ),
        },
        tags=["Auth"],
        auth=[],
        description="Login endpoint. Limited to 5 requests per minute per IP.",
    )
    def post(self, request):
        serializer = EmailTokenObtainSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=LogoutSerializer,
        responses={
            200: BaseResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Invalid or already blacklisted refresh token."
            ),
            401: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Authentication credentials were not provided."
            ),
        },
        tags=["Auth"],
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "Logged out successfully"},
            status=status.HTTP_200_OK
        )

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={
            200: UserResponseSerializer,
            401: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Authentication credentials were not provided."
            ),
        },
        tags=["Users"],
    )
    def get(self, request):
        return Response({
            "success": True,
            "message": "",
            "data": UserSerializer(request.user).data
        }, status=status.HTTP_200_OK)

class CompleteProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=BaseUserProfileSerializer,
        responses={
            200: BaseResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Validation error. All required profile fields must be provided."
            ),
            401: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Authentication required."
            ),
        },
        tags=["Users"],
    )
    def patch(self, request):
        serializer = BaseUserProfileSerializer(
            request.user,
            data=request.data,
            partial=False
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "success": True,
            "message": "Profile completed successfully"
        }, status=status.HTTP_200_OK)

class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=BaseUserProfileSerializer,
        responses={
            200: UserResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Validation error."
            ),
            401: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Authentication required."
            ),
        },
        tags=["Users"],
    )
    def patch(self, request):
        serializer = BaseUserProfileSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "success": True,
            "message": "Profile updated successfully",
            "data": UserSerializer(request.user).data
        })

class BecomeHostView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=HostActivationSerializer,
        responses={
            200: HostResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="User is already an active host."
            ),
            401: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Authentication required."
            ),
        },
        tags=["Users"],
    )
    def patch(self, request):
        host_profile, _ = HostProfile.objects.get_or_create(user=request.user)

        if host_profile.is_host:
            return Response({
                "success": False,
                "message": "You are already an active host"
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = HostActivationSerializer(host_profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(is_host=True)

        return Response({
            "success": True,
            "message": "You are now a host!",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

class RequestPasswordResetView(APIView):
    throttle_classes = [PasswordResetRateThrottle]
    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={
            200: BaseResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Invalid email format."
            ),
            429: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Too many reset requests. Try again later."
            ),
        },
        tags=["Auth"],
        auth=[],
        description="Request password reset. Limited to 3 requests per hour per IP.",
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()

        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}"

            html_content = render_to_string(
                "emails/reset_password.html",
                {"reset_link": reset_link}
            )

            email_obj = EmailMultiAlternatives(
                subject="Reset your password",
                body="Reset your password",
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email],
            )

            email_obj.attach_alternative(html_content, "text/html")
            email_obj.send()

        return Response(
            {"success": True, "message": "If the email exists, a reset link was sent"},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={
            200: BaseResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Invalid or expired reset token."
            ),
        },
        tags=["Auth"],
        auth=[],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "Password updated successfully"},
            status=status.HTTP_200_OK
        )

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=EmailVerificationSerializer,
        responses={
            200: BaseResponseSerializer,
            400: OpenApiResponse(
                response=ErrorResponseSerializer,
                description="Invalid or expired verification token."
            ),
        },
        tags=["Auth"],
        auth=[]
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "Email verified successfully"},
            status=status.HTTP_200_OK
        )