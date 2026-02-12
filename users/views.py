from .models import HostProfile, User

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from drf_spectacular.utils import extend_schema
from .serializers import BaseUserProfileSerializer, BecomeHostResponseSerializer, EmailVerificationSerializer, HostActivationSerializer, MeResponseSerializer, MessageResponseSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer, RegisterSerializer, TokenResponseSerializer, UserMessageResponseSerializer,UserSerializer,EmailTokenObtainSerializer,LogoutSerializer

from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from drf_spectacular.utils import extend_schema, extend_schema_view

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.core.mail import send_mail
from django.conf import settings
from django.utils.encoding import force_bytes

@extend_schema_view(
    post=extend_schema(
        tags=["Auth"],
        request=TokenRefreshSerializer,
        responses={200: TokenRefreshSerializer},
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
        responses={201: MessageResponseSerializer},
        tags=["Auth"],
        auth=[],
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
    permission_classes = [AllowAny]

    @extend_schema(
        request=EmailTokenObtainSerializer,
        responses=TokenResponseSerializer,
        tags=["Auth"],
        auth=[]
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
        responses={200: MessageResponseSerializer},
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
        responses={200: MeResponseSerializer},
        tags=["Users"],
    )
    def get(self, request):
        data = MeResponseSerializer({
            "success": True,
            "data": request.user
        }).data

        return Response(data, status=200)


class CompleteProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=BaseUserProfileSerializer,
        responses={200: MessageResponseSerializer},
        tags=["Users"],
    )
    def patch(self, request):
        serializer = BaseUserProfileSerializer(
            request.user,
            data=request.data,
            partial=False  # obligamos a enviar los 3 campos
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "success": True,
            "message": "Profile completed successfully"
        }, status=status.HTTP_200_OK)


class BecomeHostView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=HostActivationSerializer,
        responses={200: BecomeHostResponseSerializer},
        tags=["Users"],
    )
    def patch(self, request):
        host_profile, created = HostProfile.objects.get_or_create(user=request.user)

        if host_profile.is_host:
            return Response({
                "success": False,
                "message": "You are already an active host"
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = HostActivationSerializer(host_profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(is_host=True, months_hosting=0, total_reviews=0)

        return Response({
            "success": True,
            "message": "You are now a host!",
            "data": serializer.data
        }, status=status.HTTP_200_OK)


class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=BaseUserProfileSerializer,
        responses=UserMessageResponseSerializer,
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


        
class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses=MessageResponseSerializer,
        tags=["Auth"],
        auth=[],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()

        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # 👇 PÉGALO JUSTO AQUÍ
            print("UID:", uid)
            print("TOKEN:", token)

            reset_link = f"http://localhost:4200/reset-password/{uid}/{token}"

            send_mail(
                "Reset your password",
                f"Click here to reset your password: {reset_link}",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

        return Response({
            "success": True,
            "message": "If the email exists, a reset link was sent"
        })

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses=MessageResponseSerializer,
        tags=["Auth"],
        auth=[],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": True, "message": "Password updated successfully"},
                status=200
            )

        return Response(
            {"success": False, "errors": serializer.errors},
            status=400
        )

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=EmailVerificationSerializer,
        responses=MessageResponseSerializer,
        tags=["Auth"],
        auth=[],
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"success": True, "message": "Email verified successfully"},
                status=200
            )

        return Response(
            {"success": False, "errors": serializer.errors},
            status=400
        )