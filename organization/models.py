from django.db import models
from django.conf import settings
from django.db import models
from accounts.utils import send_notification
from accounts.models import User, UserProfile

# Create your models here.
class Organization(models.Model):
    user = models.OneToOneField(User, related_name='user', on_delete=models.CASCADE)
    user_profile = models.OneToOneField(UserProfile, related_name='userprofile', on_delete=models.CASCADE)
    organization_name = models.CharField(max_length=50, unique=True)
    organization_license = models.ImageField(upload_to='organization/license')
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.organization_name
    
    def save(self, *args, **kwargs):
        if self.pk is not None:
            orig = Organization.objects.get(pk=self.pk)
            if orig.is_approved != self.is_approved:
                mail_template = "accounts/emails/admin_approval_email.html"
                context = {
                    'user': self.user,
                    'is_approved': self.is_approved,
                }
                if self.is_approved == True:
                    mail_subject = "Congratulations! Your Organization has been approved."
                    send_notification(mail_subject, mail_template, context)
                else:
                    mail_subject = "We're sorry! Your are not eligible." 
                    send_notification(mail_subject, mail_template, context)
        return super(Organization, self).save(*args, **kwargs)
