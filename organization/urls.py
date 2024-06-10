from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import EventViewSet, VolunteerForEventAPIView

router = DefaultRouter()
router.register(r'events', EventViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('api/events/volunteer/', VolunteerForEventAPIView.as_view(), name='volunteer_for_event'),
]