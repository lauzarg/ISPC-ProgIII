from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    OTPVerifyView,
    PasswordResetRequestView,
    PasswordResetConfirmView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/otp/', OTPVerifyView.as_view(), name='login-otp'),
    path('password/forgot/', PasswordResetRequestView.as_view(), name='password-forgot'),
    path('password/reset/', PasswordResetConfirmView.as_view(), name='password-reset'),
]