from rest_framework import viewsets, status
from .models import Event
from .serializers import EventSerializer
from django.contrib.contenttypes.models import ContentType
from rest_framework.response import Response
# from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticatedOrReadOnly


# Create your views here.
# @csrf_exempt
class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def create(self, request, *args, **kwargs):
        object_type = request.data.get('object_type')
        object_id = request.data.get('object_id')
        
        try:
            content_type = ContentType.objects.get(model=object_type)
            model_class = content_type.model_class()
            if not model_class.objects.filter(id=object_id).exists():
                return Response({'error: Invalid Object ID for the given type. '}, status=status.HTTP_400_BAD_REQUEST)
            
            request.data['content_type'] = content_type.pk
            request.data[object_id] = object_id
        except ContentType.DoesNotExist:
            return Response({'error': 'Invalid object type. '}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
