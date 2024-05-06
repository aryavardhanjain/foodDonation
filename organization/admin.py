from django.contrib import admin
from .models import Organization, Event, Volunteer

# Register your models here.
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization_name', 'is_approved', 'created_at')
    list_display_links = ('user', 'organization_name')

class EventAdmin(admin.ModelAdmin):
    list_display = ('title', 'date', 'volunteer_count')
    readonly_fields = ('volunteer_count',) 


admin.site.register(Event, EventAdmin)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(Volunteer)