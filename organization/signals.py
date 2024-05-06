from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Volunteer

@receiver(post_save, sender=Volunteer)
def update_volunteer_count(sender, instance, created, **kwargs):
    if created:
        event = instance.event
        event.volunteer_count += 1
        event.save()

@receiver(post_delete, sender=Volunteer)
def decrease_volunteer_count(sender, instance, **kwargs):
    event = instance.event
    event.volunteer_count -= 1
    event.save()