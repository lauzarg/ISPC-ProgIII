from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegisterSerializer,
    UserSerializer,
    LoginSerializer,
    OTPVerifySerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
)
from .models import LoginOTP, PasswordResetToken
import random

# Create your views here.

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

class LoginView(APIView):
    """
    Paso 1 del login: validar usuario/clave y generar OTP.
    El OTP se imprime en la consola del servidor.
    """
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(username=username, password=password)
        if not user:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        code = f"{random.randint(0, 999999):06d}"
        LoginOTP.objects.create(user=user, code=code)

        # Consigna: mostrarlo en la consola (no enviar email todavía)
        print(f"OTP para usuario {user.username}: {code}")

        return Response(
            {'detail': 'OTP generado. Revisar consola del servidor.'},
            status=status.HTTP_200_OK
        )

class OTPVerifyView(APIView):
    """
    Paso 2 del login: verificar OTP y devolver tokens JWT.
    """
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        code = serializer.validated_data['code']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {'error': 'OTP inválido'},
                status=status.HTTP_400_BAD_REQUEST
            )

        otp = (
            LoginOTP.objects
            .filter(user=user, is_used=False)
            .order_by('-created_at')
            .first()
        )

        if not otp or otp.is_expired() or otp.code != code:
            return Response(
                {'error': 'OTP inválido o expirado'},
                status=status.HTTP_400_BAD_REQUEST
            )

        otp.is_used = True
        otp.save()

        refresh = RefreshToken.for_user(user)
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data,
        }
        return Response(data, status=status.HTTP_200_OK)

class PasswordResetRequestView(APIView):
    """
    Solicitar recuperación de cuenta: genera un token
    y lo imprime en consola.
    """
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # No revelamos si existe o no el email.
            return Response(
                {'detail': 'Si el email existe, se ha enviado un enlace de recuperación.'},
                status=status.HTTP_200_OK
            )

        reset_token = PasswordResetToken.objects.create(user=user)

        print(f"Token de recuperación para {user.email}: {reset_token.token}")

        return Response(
            {'detail': 'Si el email existe, se ha enviado un enlace de recuperación.'},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    """
    Confirmar recuperación: recibir token + nueva contraseña.
    """
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            reset = PasswordResetToken.objects.get(token=token, is_used=False)
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Token inválido'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if reset.is_expired():
            return Response(
                {'error': 'Token expirado'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = reset.user
        user.set_password(new_password)
        user.save()

        reset.is_used = True
        reset.save()

        return Response(
            {'detail': 'Contraseña actualizada correctamente.'},
            status=status.HTTP_200_OK
        )
