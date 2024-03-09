from django.contrib import admin
from .models import Organization, Event

# Register your models here.
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization_name', 'is_approved', 'created_at')
    list_display_links = ('user', 'organization_name')


admin.site.register(Event)
admin.site.register(Organization, OrganizationAdmin)