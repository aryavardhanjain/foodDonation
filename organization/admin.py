from django.contrib import admin
from .models import Organization

# Register your models here.
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization_name', 'is_approved', 'created_at')
    list_display_links = ('user', 'organization_name')

admin.site.register(Organization, OrganizationAdmin)