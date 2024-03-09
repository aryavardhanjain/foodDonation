from rest_framework import serializers
from django.contrib.contenttypes.models import ContentType
from .models import Event, User, Organization

class EventSerializer(serializers.ModelSerializer):
    date = serializers.DateTimeField(format='%d-%m-%Y', input_formats=['%d-%m-%Y', 'iso-8601'])
    time = serializers.DateTimeField(format='%H:%M:%S', input_formats=['%H:%M:%S', 'iso-8601'])
    
    class Meta:
        model = Event
        fields = '__all__'