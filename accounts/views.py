from .models import User, Report, Rating, User, FoodDonation
from organization.models import Organization
from django.contrib.auth import logout
from django.conf import settings
from django.contrib import auth
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from .utils import detectUser, send_verification_email, send_notification
from django.core.exceptions import PermissionDenied
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import ReportSerializer, RatingSerializer, UserSerializer, OrganizationSerializer, FoodDonationSerializer
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.db import transaction
import logging
from rest_framework.decorators import action
from django.core.mail import send_mail


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
                user_data['organization_created_at'] = organization_data['created_at'] 
                user_data['organization_id'] = organization_data.get('id', 'Not available')
            except Organization.DoesNotExist:
                user_data['organization'] = None
                user_data['organization_created_at'] = organization_data.get('created_at', 'Not available')  
                user_data['organization_id'] = 'Not available'

            return Response({'message': 'You are now logged in.', 'token': token.key, 'user': user_data}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid login credentials! Please try again.'}, status=status.HTTP_401_UNAUTHORIZED)

    def get(self, request, *args, **kwargs):
        return JsonResponse({'detail': 'POST request expected.'}, status=status.HTTP_400_BAD_REQUEST)

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            logout(request)
            return Response({'message': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class MyAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        redirectUrl = detectUser(user)
        return Response({'redirect_url': redirectUrl})

class DonorDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.role == 2:
            return Response({'error': 'Access denied'})
        return Response({'success': 'Donor Dashboard'})

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

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

class RatingViewSet(viewsets.ModelViewSet):
    queryset = Rating.objects.all()
    serializer_class = RatingSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def create(self, request, *args, **kwargs):
        # Extract organization_id from URL
        organization_id = kwargs.get('organization_id')
        try:
            # Fetch the organization object
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            return Response({'error': 'Organization not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        # Create a serializer with data and extra organization info
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Save the new Rating object with the organization and user
            serializer.save(organization=organization, rated_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RatingByOrganizationAPIView(APIView):
    def get(self, request, *args, **kwargs):
        organization_name = request.query_params.get('organization_name')
        if not organization_name:
            return Response({'error': 'Parameter organization_name required'}, status=status.HTTP_400_BAD_REQUEST)
        
        print("Querying for organization named:", organization_name)

        try:
            organization = Organization.objects.get(organization_name=organization_name)
        except Organization.DoesNotExist:
            return Response({'error': 'Organization not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        ratings = Rating.objects.filter(organization=organization)
        serializer = RatingSerializer(ratings, many=True)
        return Response(serializer.data)
    
class FoodDonationViewSet(viewsets.ModelViewSet):
    queryset = FoodDonation.objects.all()
    serializer_class = FoodDonationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(donor=self.request.user)

    @action(detail=True, methods=['post'])
    def change_status(self, request, pk=None):
        donation = self.get_object()
        status = request.data.get('status')
        if status in ['Accepted', 'Declined']:
            donation.status = status
            donation.save()
            self.send_status_email(donation)
            return Response({'status': 'Status changed'})
        return Response({'status': 'Invalid status'})
    
    def send_status_email(self, donation):
        mail_subject = f"Your donation application has been {donation.status}"
        context = {
            'user': donation.donor,
            'username': donation.donor.username,
            'food_type': donation.food_type,
            'status': donation.status.lower(),
        }
        send_notification(mail_subject, 'accounts/emails/donation_status_email.html', context) 