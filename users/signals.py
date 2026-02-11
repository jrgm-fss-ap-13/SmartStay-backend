from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, HostProfile

@receiver(post_save, sender=User)
def create_host_profile(sender, instance, created, **kwargs):
    if created:
        HostProfile.objects.create(user=instance)