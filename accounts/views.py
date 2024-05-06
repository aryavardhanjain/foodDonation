# from django.http import JsonResponse
from .models import User, Report, Rating, User
from organization.models import Organization
from django.contrib.auth import logout
from django.contrib import auth
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json
# from organization.models import Organization
from .utils import detectUser, send_verification_email
# from django.shortcuts import redirect
# from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.exceptions import PermissionDenied
# from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import ReportSerializer, RatingSerializer, UserSerializer, OrganizationSerializer
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
import logging

logger = logging.getLogger(__name__)


# Create your views here.
def check_role_organization(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied
    
def check_role_donor(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied

class RegisterUserAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data, context={'role': User.DONOR})
        if serializer.is_valid():
            user = serializer.save()
            send_verification_email(request, user, 'Please activate your account', 'accounts/emails/account_verification_email.html')
            return Response({'message': 'Registration successful! Account activation link has been sent to your email account. '}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserActiveCheckAPIView(APIView):
    def get(self, request, *args, **kwargs):
        email = request.query_params.get('email', None)
        if email is None:
            return Response({'error': 'Parameter email required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            return Response(user.is_active, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

class RegisterOrganizationAPIView(APIView):
        def post(self, request):
            with transaction.atomic():
                user_serializer = UserSerializer(data=request.data, context={'role': User.ORGANIZATION})
                if user_serializer.is_valid():
                    user = user_serializer.save()
                    organization_data = {
                        'user': user.id,
                        'organization_name': request.data.get('organization_name'),
                        'chairman_name': request.data.get('chairman_name'),
                        'phone_number': request.data.get('phone_number'),
                        'registered_address': request.data.get('registered_address'),
                    }

                    organization_serializer = OrganizationSerializer(data=organization_data)
                    if organization_serializer.is_valid():
                        organization = organization_serializer.save()
                        send_verification_email(request, user, 'Please activate your account', 'accounts/emails/account_verification_email.html')
                        return Response({'success': 'Registration successful! Activation link sent successfully.'}, status=status.HTTP_201_CREATED)
                    else:
                        return Response({'errors': organization_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'errors': user_serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class UploadLicenseAPIView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, organization_id):
        try:
            organization = Organization.objects.get(id=organization_id)
            organization.organization_license = request.FILES.get('license')
            organization.save()
            return Response({'message': 'License uploaded successfully.'}, status=status.HTTP_200_OK)
        except Organization.DoesNotExist:
            return Response({'error': 'Organization not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return JsonResponse({'message': 'You are already logged in.'}, status=status.HTTP_200_OK)

        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = auth.authenticate(request=request, username=email, password=password)
        if user is not None:
            auth.login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            user_data = UserSerializer(user).data
            return JsonResponse({'message': 'You are now logged in.', 'token': token.key, 'user': user_data}, status=status.HTTP_200_OK)
        else:
            return JsonResponse({'error': 'Invalid login credentials! Please try again.'}, status=status.HTTP_401_UNAUTHORIZED)

    def get(self, request, *args, **kwargs):
        return JsonResponse({'detail': 'POST request expected.'}, status=status.HTTP_400_BAD_REQUEST)

class LoginOrganizationAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return JsonResponse({'message': 'You are already logged in.'}, status=status.HTTP_200_OK)

        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = auth.authenticate(request=request, username=email, password=password)
        if user is not None:
            auth.login(request, user)
            token, _ = Token.objects.get_or_create(user=user)
            user_data = UserSerializer(user).data
            try:
                organization = Organization.objects.get(user=user)
                organization_data = OrganizationSerializer(organization).data
                user_data['organization'] = organization_data
                user_data['organization_created_at'] = organization_data['created_at']  # Add the organization's created_at
            except Organization.DoesNotExist:
                user_data['organization'] = None
                user_data['organization_created_at'] = organization_data.get('created_at', 'Not available')  # Add the organization's created_at

            return Response({'message': 'You are now logged in.', 'token': token.key, 'user': user_data}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid login credentials! Please try again.'}, status=status.HTTP_401_UNAUTHORIZED)

    def get(self, request, *args, **kwargs):
        return JsonResponse({'detail': 'POST request expected.'}, status=status.HTTP_400_BAD_REQUEST)

# def logout(request):
#     if request.user.is_authenticated:
#         auth.logout(request)
#         return JsonResponse({'message': 'You have been successfully logged out.'})
#     else:
#         return JsonResponse({'error': 'You are not logged in.'}, status=400)

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            logout(request)
            return Response({'message': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# @login_required(login_url='login')    
# def myAccount(request):
#     user = request.user
#     redirectUrl = detectUser(user)
#     return redirect(redirectUrl)

class MyAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        redirectUrl = detectUser(user)
        return Response({'redirect_url': redirectUrl})

# @login_required(login_url='login')    
# @user_passes_test(check_role_customer)
# def custDashboard(request):
#     return

class DonorDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.role == 2:
            return Response({'error': 'Access denied'})
        return Response({'success': 'Donor Dashboard'})

# @login_required(login_url='login')   
# @user_passes_test(check_role_organization) 
# def orgDashboard(request):
#     return

class OrganizationDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.role == 1:
            return Response({'error': 'Access denied'})
        else:
            return Response({'success': 'Organization Dashboard'})
        
class ActivateAccountAPIView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            if user is not None and default_token_generator.check_token(user, token):
                user.is_active = True
                user.save()
                user_data = UserSerializer(user).data
                return Response({'message': 'Account activated successfully.', 'user': user_data}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid activation link.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# def activate(request, uidb64, token):
#     User = get_user_model()

#     try:
#         uid = urlsafe_base64_decode(uidb64).decode()
#         user = User._default_manager.get(pk=uid)
#     except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#         user = None

#     if user is not None and default_token_generator.check_token(user, token):
#         user.is_active = True
#         user.save()
#         return JsonResponse({'message': 'Account activated successfully.'})
#     else:
#         return JsonResponse({'error': 'Invalid activation link.'}, status=401)

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

    # def perform_create(self, serializer):
    #     serializer.save(reported_by=self.request.user)

class RatingViewSet(viewsets.ModelViewSet):
    queryset = Rating.objects.all()
    serializer_class = RatingSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(rated_by=self.request.user)