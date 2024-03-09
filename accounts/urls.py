from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

router = DefaultRouter()
router.register(r'reports', views.ReportViewSet)
router.register(r'ratings', views.RatingViewSet)

urlpatterns = [
    path('registerUser/', views.registerUser, name='registerUser'),
    # path('uploadImage/', views.uploadImage, name='uploadImage'),
    path('uploadLicense/<str:organization_name>/', views.uploadLicense, name='uploadLicense'),
    path('registerOrganization/', views.registerOrganization, name='registerOrganization'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('myAccount/', views.myAccount, name='myAccount'),
    path('custDashboard/', views.custDashboard, name='custDashboard'),
    path('orgDashboard/', views.orgDashboard, name='orgDashboard'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('api/', include(router.urls)),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
] 