from rest_framework import serializers
from .models import Report, Rating
from django.db import IntegrityError

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