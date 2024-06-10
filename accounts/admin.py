from django.contrib import admin
from .models import User, UserProfile, Rating, Report, FoodDonation
from django.contrib.auth.admin import UserAdmin
from django.contrib.contenttypes.models import ContentType

# Register your models here.
class ContentTypeAdmin(admin.ModelAdmin):
    list_display = ('id', 'app_label', 'model')
    search_fields = ('app_label', 'model')

class CustomerUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'username','role' ,'is_active')
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    ordering = ('-date_joined', )

class ReportAdmin(admin.ModelAdmin):
    list_display = ('content_object', 'reason', 'reported_by', 'created_at')
    list_filter = ('reason', 'created_at')
    search_fields = ('reason', 'reported_by__email', 'content_object__username')

class FoodDonationAdmin(admin.ModelAdmin):
    list_display = ('name_donor', 'food_type', 'delivery_method', 'status')

admin.site.register(User, CustomerUserAdmin)
admin.site.register(UserProfile)
admin.site.register(Rating)
admin.site.register(Report, ReportAdmin)
admin.site.register(ContentType, ContentTypeAdmin)
admin.site.register(FoodDonation, FoodDonationAdmin)