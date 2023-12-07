from django import forms

from organization.models import Organization

class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ['organization_name', 'organization_license']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['organization_license'].required = False