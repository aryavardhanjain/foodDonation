# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from .models import User, UserProfile

# @receiver(post_save, sender=User)
# def post_save_create_profile_receiver(sender, instance, created, **kwargs):
#     if created:
#         UserProfile.objects.create(user=instance)
#     else:
#         try:
#             profile = UserProfile.objects.get(user=instance)
#             profile.save()
#         except:
#             UserProfile.objects.create(user=instance)

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, UserProfile
import logging

logger = logging.getLogger(__name__)

@receiver(post_save, sender=User)
def post_save_create_profile_receiver(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        logger.info(f'UserProfile created for {instance.email}')
    else:
        try:
            profile = UserProfile.objects.get(user=instance)
            profile.save()  # Consider what you are trying to achieve with this save.
        except UserProfile.DoesNotExist:
            UserProfile.objects.get_or_create(user=instance)
            logger.info(f'UserProfile created for {instance.email} on update')