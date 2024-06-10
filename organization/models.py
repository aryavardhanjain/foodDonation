from django.db import models
from django.db import models
from accounts.utils import send_notification
from accounts.models import User, UserProfile

# Create your models here.
class Organization(models.Model):
    user = models.OneToOneField(User, related_name='user', on_delete=models.CASCADE)
    user_profile = models.OneToOneField(UserProfile, related_name='userprofile', on_delete=models.CASCADE)
    organization_name = models.CharField(max_length=50, unique=True)
    organization_license = models.ImageField(upload_to='organization/license', blank=True)
    chairman_name = models.CharField(max_length=255, default='')
    registered_address = models.TextField(max_length=1024, default = '')
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

class Event(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='events', default='')
    title = models.CharField(max_length=100)
    description = models.TextField()
    date = models.TextField(default='')
    time = models.TextField(default='')
    latitude = models.TextField(default='', blank=True, null=True)
    longitude = models.TextField(default='', blank=True, null=True)
    location = models.CharField(max_length=255)
    volunteers = models.ManyToManyField(User, related_name='volunteered_events', through='Volunteer')
    volunteer_count = models.PositiveIntegerField(default=0, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
    
class Volunteer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='volunteer_profiles')
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='volunteer_list')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'event')

    def __str__(self):
        return f"{self.user.email} volunteered for {self.event.title}"