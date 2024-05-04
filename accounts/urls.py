# from django.urls import path, include
# from . import views
# from rest_framework.routers import DefaultRouter
# from rest_framework_simplejwt.views import (
#     TokenObtainPairView,
#     TokenRefreshView,
# )

# router = DefaultRouter()
# router.register(r'reports', views.ReportViewSet)
# router.register(r'ratings', views.RatingViewSet)

# urlpatterns = [
#     path('registerUser/', views.registerUser, name='registerUser'),
#     # path('uploadImage/', views.uploadImage, name='uploadImage'),
#     path('uploadLicense/<str:organization_name>/', views.uploadLicense, name='uploadLicense'),
#     path('registerOrganization/', views.registerOrganization, name='registerOrganization'),
#     path('login/', views.login, name='login'),
#     path('logout/', views.logout, name='logout'),
#     path('myAccount/', views.myAccount, name='myAccount'),
#     path('custDashboard/', views.custDashboard, name='custDashboard'),
#     path('orgDashboard/', views.orgDashboard, name='orgDashboard'),
#     path('activate/<uidb64>/<token>/', views.activate, name='activate'),
#     path('api/', include(router.urls)),
#     path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
#     path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
# ] 

from django.urls import path, include
from .views import (
    RegisterUserAPIView, RegisterOrganizationAPIView,
    LoginAPIView, LogoutAPIView, ActivateAccountAPIView,
    MyAccountAPIView, DonorDashboardAPIView,
    OrganizationDashboardAPIView, ReportViewSet, RatingViewSet
)
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'reports', ReportViewSet)
router.register(r'ratings', RatingViewSet)

urlpatterns = [
    path('api/register-user/', RegisterUserAPIView.as_view(), name='register_user'),
    path('api/register-organization/', RegisterOrganizationAPIView.as_view(), name='register_organization'),
    path('api/login/', LoginAPIView.as_view(), name='login'),
    path('api/logout/', LogoutAPIView.as_view(), name='logout'),
    path('api/my-account/', MyAccountAPIView.as_view(), name='my_account'),
    path('api/customer-dashboard/', DonorDashboardAPIView.as_view(), name='customer_dashboard'),
    path('api/organization-dashboard/', OrganizationDashboardAPIView.as_view(), name='organization_dashboard'),
    path('api/activate/<uidb64>/<token>/', ActivateAccountAPIView.as_view(), name='activate'),
    path('api/', include(router.urls)),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
