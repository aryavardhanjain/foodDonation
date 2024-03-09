from django.views.decorators.csrf import csrf_exempt
import json
from django.http import JsonResponse
from .forms import UserForm
from .models import User, UserProfile, Report, Rating
from organization.forms import OrganizationForm
from organization.models import Organization
from django.contrib import auth
from .utils import detectUser, send_verification_email
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from rest_framework import viewsets
from .serializers import ReportSerializer, RatingSerializer
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated

# Create your views here.
def check_role_organization(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied
    
def check_role_customer(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied

@csrf_exempt
def registerUser(request):
    if request.user.is_authenticated:
        return JsonResponse({'message': 'You are already logged in. '})
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            form = UserForm(data)
            if form.is_valid():
                first_name = form.cleaned_data['first_name']
                last_name = form.cleaned_data['last_name']
                username = form.cleaned_data['username']
                email = form.cleaned_data['email']
                password = form.cleaned_data['password']

                user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
                user.role = User.CUSTOMER
                user.save()
                mail_subject = 'Please activate your account'
                email_template = 'accounts/emails/account_verification_email.html'
                send_verification_email(request, user, mail_subject, email_template)
                return JsonResponse({'message': 'Registration successful. Account activation link has been sent to your email account.'}, status = 201)
            else:
                return JsonResponse({'errors': form.errors}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data.'}, status=400)
    else:
        return JsonResponse({'message': 'Invalid request method. '}, status=400)
    
@csrf_exempt
def registerOrganization(request):
    if request.user.is_authenticated:
        return JsonResponse({'message': 'You are already logged in. '})
    
    if request.method == 'POST':
        try:
            user_data = {
                'first_name': request.POST.get('user[first_name]'),
                'last_name': request.POST.get('user[last_name]'),
                'username': request.POST.get('user[username]'),
                'email': request.POST.get('user[email]'),
                'password': request.POST.get('user[password]'),
                'confirm_password': request.POST.get('user[confirm_password]')
            }

            organization_data = {
                'organization_name': request.POST.get('organization[organization_name]'),
            }

            user_form = UserForm(user_data)
            organization_form = OrganizationForm(organization_data)

            if user_form.is_valid() and organization_form.is_valid():
                user = user_form.save(commit=False)
                user.role = User.ORGANIZATION
                user.save()

                organization = organization_form.save(commit=False)
                organization.user = user
                user_profile = UserProfile.objects.get(user=user)
                organization.user_profile = user_profile
                organization.save()
                mail_subject = 'Please activate your account'
                email_template = 'accounts/emails/account_verification_email.html'
                send_verification_email(request, user, mail_subject, email_template)

                return JsonResponse({
                    'message': 'Account activation link has been sent to your email account.',
                    'message': 'Your account has been registered successfully! Please wait for the approval. '}, status=201)
            else:
                return JsonResponse({'errors': {'user': user_form.errors, 'organization': organization_form.errors}}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data.'}, status=400)
    else:
        return JsonResponse({'message': 'Invalid request method.'}, status=400)

@csrf_exempt
def uploadLicense(request, organization_name):
    try:
        organization = Organization.objects.get(organization_name=organization_name)
    except Organization.DoesNotExist:
        return JsonResponse({'message': 'Organization not found.'}, status=400)
    
    if request.method == 'POST':
        form  =OrganizationForm(request.POST, request.FILES, instance=organization)
        if form.is_valid():
            form.save()
            return JsonResponse({'message': 'Organization License uploaded.'}, status=200)
        else:
            return JsonResponse({'errors': form.errors}, status=400)
    else:
        return JsonResponse({'message': 'Invalid request method.'}, status=400)
    
@csrf_exempt
def login(request):
    if request.user.is_authenticated:
        return JsonResponse({'message': 'You are already logged in.'})
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            user = auth.authenticate(email=email, password=password)

            if user is not None:
                auth.login(request, user)
                return JsonResponse({'message': 'You are now logged in.'})
            else:
                return JsonResponse({'message': 'Invalid login credentials.'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON data.'}, status=400)
    
    return JsonResponse({'error': 'Invalid request method.'}, status=400)

def logout(request):
    if request.user.is_authenticated:
        auth.logout(request)
        return JsonResponse({'message': 'You have been successfully logged out.'})
    else:
        return JsonResponse({'error': 'You are not logged in.'}, status=400)

@login_required(login_url='login')    
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)

@login_required(login_url='login')    
@user_passes_test(check_role_customer)
def custDashboard(request):
    return

@login_required(login_url='login')   
@user_passes_test(check_role_organization) 
def orgDashboard(request):
    return

def activate(request, uidb64, token):
    User = get_user_model()

    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return JsonResponse({'message': 'Account activated successfully.'})
    else:
        return JsonResponse({'error': 'Invalid activation link.'}, status=401)

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