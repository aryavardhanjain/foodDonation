from rest_framework import serializers
from .models import Event

class EventSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Event
        fields = ['id', 'organization', 'title', 'description', 'date', 'time', 'location', 'latitude', 'longitude', 'created_at', 'updated_at']
        read_only_fields = ['organization', 'created_at', 'updated_at']