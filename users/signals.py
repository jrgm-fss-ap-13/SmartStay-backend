from django.db.models import Avg
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import HostReview, User, HostProfile

@receiver(post_save, sender=User)
def create_host_profile(sender, instance, created, **kwargs):
    if created:
        HostProfile.objects.create(user=instance)


@receiver(post_save, sender=HostReview)
def update_host_rating(sender, instance, **kwargs):

    host = instance.host
    avg = host.reviews.aggregate(avg=Avg("rating"))["avg"]
    total = host.reviews.count()
    host.rating = round(avg)
    host.total_reviews = total
    host.save()