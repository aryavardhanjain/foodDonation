from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.validators import MinValueValidator, MaxValueValidator

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("User must have an email address")
        
        user = self.model(
            email = self.normalize_email(email),
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, first_name, last_name, username, email, password=None, **extra_fields):
        user = self.create_user(
            email = self.normalize_email(email),
            username = username,
            password = password,
            first_name = first_name,
            last_name = last_name,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superadmin = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    ORGANIZATION = 1
    DONOR = 2

    ROLE_CHOICE = (
        (ORGANIZATION, 'Organization'),
        (DONOR, 'Donor')
    )
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    phone_number = models.CharField(max_length=20, default = '')
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICE, blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_superadmin = models.BooleanField(default = False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def has_perm(self, perm, obj=None):
        return self.is_admin
    
    def has_module_perms(self, app_label):
        return True
    
    def get_role(self):
        if self.role == 1:
            user_role = 'Organization'
        elif self.role == 2:
            user_role = 'Donor'
        return user_role

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True, null=True)
    address_line_1 = models.CharField(max_length=50, blank=True, null=True)
    address_line_2 = models.CharField(max_length=50, blank=True, null=True)
    country = models.CharField(max_length=15, blank=True, null=True)
    state = models.CharField(max_length=15, blank=True, null=True)
    city = models.CharField(max_length=15, blank=True, null=True)
    pin_code = models.CharField(max_length=6, blank=True, null=True)
    about = models.TextField(max_length=1000, blank=True, null=True)
    # latitude = models.CharField(max_length=20, blank=True, null=True)
    # longitude = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.email
    
class Report(models.Model):
    REPORT_REASON = [
        ('spam', 'Spam',),
        ('fake', 'Fake',),
    ]
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    objects_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'objects_id')
    reason = models.CharField(max_length=150, choices=REPORT_REASON)
    reported_by = models.ForeignKey(User, related_name='reports', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.get_reason_display()} report for {self.content_object}"
    
class Rating(models.Model):
    organization = models.ForeignKey('organization.Organization', on_delete=models.CASCADE, related_name='ratings')
    rating = models.PositiveSmallIntegerField(validators = [MinValueValidator(1), MaxValueValidator(5)])
    description = models.TextField(blank=True, null=True)
    rated_by = models.ForeignKey(User, related_name = 'ratings', on_delete = models.CASCADE)
    rated_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Rating {self.rating} for {self.organization.organization_name} by {self.rated_by}"
    
class FoodDonation(models.Model):
    FOOD_TYPES = [
        ('VEGETARIAN', 'Vegetarian'),
        ('NON-VEGETARIAN', 'Non-Vegetarian'),
        ('VEGAN', 'Vegan')
    ]

    PERISHABILITY_CHOICES = [
        ('PERISHABLE', 'Perishable'),
        ('NON-PERISHABLE', 'Non-Perishable'),
    ]

    DELIVERY_METHOD = [
        ('PICK-UP', 'Pick-Up'),
        ('DROP', 'Drop'),
    ]

    donor = models.ForeignKey(User, related_name='food_donations', on_delete=models.CASCADE)
    name_donor = models.CharField(max_length=50)
    food_type = models.CharField(max_length=50, choices=FOOD_TYPES)
    perishability = models.CharField(max_length=50, choices=PERISHABILITY_CHOICES)
    delivery_method = models.CharField(max_length=50, choices=DELIVERY_METHOD)
    quantity = models.TextField()
    status = models.CharField(max_length=20, default='Pending', choices=[('PENDING', 'Pending'), ('ACCEPTED', 'Accepted'), ('REJECTED', 'Rejected')])
    scheduled_date = models.TextField()
    scheduled_time = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.food_type} ({self.perishability}) - {self.delivery_method} donation by {self.donor}"