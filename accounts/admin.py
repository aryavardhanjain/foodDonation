from django.contrib import admin
from .models import User, UserProfile
from django.contrib.auth.admin import UserAdmin

# Register your models here.
class CustomerUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'username','role' ,'is_active')
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    ordering = ('-date_joined', )

admin.site.register(User, CustomerUserAdmin)
admin.site.register(UserProfile)