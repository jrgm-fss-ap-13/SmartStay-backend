from django.urls import path
from .views import BecomeHostView,CompleteProfileView, LogoutView, PasswordResetConfirmView, RegisterView, RequestPasswordResetView
from .views import UpdateProfileView, UserProfileView, EmailLoginView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path('login/', EmailLoginView.as_view(), name='email-login'),
    path('logout/', LogoutView.as_view(), name='logout'),

    path("me/", UserProfileView.as_view(), name="profile"),
    path('become-host/', BecomeHostView.as_view(), name='become-host'),
    path("update-me/",UpdateProfileView.as_view(), name='update-me'),
    path("complete-profile/", CompleteProfileView.as_view(), name="complete-profile"),

    path("request-password-reset/", RequestPasswordResetView.as_view()),
    path("reset-password-confirm/", PasswordResetConfirmView.as_view()),
]