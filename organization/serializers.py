from rest_framework import serializers
from .models import Event

class EventSerializer(serializers.ModelSerializer):
    date = serializers.DateTimeField(format='%d-%m-%Y', input_formats=['%d-%m-%Y', 'iso-8601'])
    time = serializers.DateTimeField(format='%H:%M:%S', input_formats=['%H:%M:%S', 'iso-8601'])
    
    class Meta:
        model = Event
        fields = ['id', 'organization', 'title', 'description', 'date', 'time', 'location', 'latitude', 'longitude', 'created_at', 'updated_at']
        read_only_fields = ['organization', 'created_at', 'updated_at']