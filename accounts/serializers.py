from rest_framework import serializers
from .models import Report, Rating, User
from django.db import IntegrityError
from organization.models import Organization
import uuid

class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'password', 'role', 'confirm_password']
        extra_kwargs = {
            'password' : {'write_only': True},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'username': {'required': False}
        }

    def create(self, validated_data):
        email = validated_data['email'].lower()
        user = User(
            email=email,
            username=validated_data.get('username', self.create_unique_username()),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        user.set_password(validated_data['password'])
        user.role = validated_data.get('role', User.DONOR)
        user.save()
        return user
    
    @staticmethod
    def create_unique_username():
        return uuid.uuid4().hex[:30]
    
    def validate(self, data):
        if data['password'] != data.pop('confirm_password'):
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        role = data.get('role')
        if role == User.ORGANIZATION:
            # Organizations might not need these fields
            pass
        else:
            # Normal users must have these fields
            if not data.get('first_name') or not data.get('last_name') or not data.get('username'):
                raise serializers.ValidationError("First name, last name, and username are required for normal users.")
        return data
    
    def validate_email(self, value):
        value = value.lower()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

class OrganizationSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), write_only=True)

    class Meta:
        model = Organization
        fields = ['user', 'organization_name', 'chairman_name', 'phone_number', 'registered_address', 'organization_license', 'is_approved']
        read_only_fields = ['is_approved', 'user']

    def create(self, validated_data):
        return Organization.objects.create(**validated_data)

class ReportSerializer(serializers.ModelSerializer):
    reported_by_email = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at', 'reported_by')
    
    def get_reported_by_email(self, obj):
        return obj.reported_by.email
    
    def validate_reason(self, value):
        if value not in [choice[0] for choice in Report.REPORT_REASON]:
            raise serializers.ValidationError("Invalid reason to report. ")
        return value
    
    def create(self, validated_data):
        user = self.context['request'].user

        try:
            report = Report.objects.create(**validated_data, reported_by=user)
            return report
        except IntegrityError as e:
            raise serializers.ValidationError({'detail': str(e)})
        
class RatingSerializer(serializers.ModelSerializer):
    rated_by_email = serializers.SerializerMethodField()

    class Meta:
        model = Rating
        fields = '__all__'
        read_only_fields = ('rated_on', 'rated_by')

    def get_rated_by_email(self, obj):
        return obj.rated_by.email
    
    def validate_rating(self, value):
        if not (1 <= value <= 5):
            raise serializers.ValidationError('Rating must be between 1 and 5. ')
        return value