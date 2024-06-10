from rest_framework import viewsets, status
from .models import Event, Organization, Volunteer
from django.core.exceptions import PermissionDenied
from .serializers import EventSerializer
from rest_framework.response import Response
# from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.views import APIView


class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]

    def perform_create(self, serializer):
        try:
            organization = Organization.objects.get(user=self.request.user)
        except Organization.DoesNotExist:
            raise PermissionDenied('Only users associated with an organization can create events.')

        serializer.save(organization=organization)

class VolunteerForEventAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        event_id = request.query_params.get('event_id')
        if not event_id:
            return Response({'error': 'Event ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            event = Event.objects.get(id=event_id)
            Volunteer.objects.create(user=request.user, event=event)
            return Response({'message': 'You have successfully volunteered for the event.'}, status=status.HTTP_201_CREATED)
        except Event.DoesNotExist:
            return Response({'error': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)