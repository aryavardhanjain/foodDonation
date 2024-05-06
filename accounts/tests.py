from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from .models import User, UserProfile
from organization.models import Organization


class OrganizationRegistrationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
        email='test@example.com',
        password='securepassword123'
    )


    def test_register_organization_success(self):
        """Test successful organization registration."""
        url = reverse('register_organization')
        data = {
            'email': 'test1@example.com',
            'password': 'securepassword123',
            'confirm_password': 'securepassword123',
            'role': User.ORGANIZATION,
            'organization_name': 'Test Org',
            'chairman_name': 'Jane Doe',
            'phone_number': '1234567890',
            'registered_address': '1234 Test St',
        }
        response = self.client.post(url, data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print(response.data)  # Print response data for debugging
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_user_profile_creation(self):
        """Ensure that a UserProfile is created for each new user."""
        # Directly check for UserProfile existence linked to the user.
        profile_exists = UserProfile.objects.filter(user=self.user).exists()
        self.assertTrue(profile_exists, "UserProfile should be automatically created with the user")
        
    def test_register_organization_password_mismatch(self):
        """Test registration with a password mismatch."""
        url = reverse('register_organization')
        data = {
            'email': 'test@example.com',
            'password': 'password123',
            'confirm_password': 'password321',
            'organization_name': 'Test Org',
            'chairman_name': 'Jane Doe',
            'phone_number': '1234567890',
            'registered_address': '1234 Test St'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Organization.objects.exists())
