from django.urls import path
from . import views

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
] 