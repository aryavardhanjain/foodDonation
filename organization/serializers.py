from rest_framework import serializers
from .models import Event
from accounts.serializers import OrganizationSerializer, UserSerializer

class EventSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)
    class Meta:
        model = Event
        fields = ['id', 'organization', 'title', 'description', 'date', 'time', 'location', 'latitude', 'longitude', 'volunteer_count', 'created_at', 'updated_at']
        read_only_fields = ['organization', 'created_at', 'updated_at']