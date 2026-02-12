from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework.fields import MaxValueValidator, MinValueValidator

# Create your models here.
class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True)
    profile_image = models.URLField(blank=True)

    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

class HostProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='host_profile')

    is_host = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    phone = models.CharField(max_length=20, blank=True)

    months_hosting = models.PositiveIntegerField(default=0)
    profession = models.CharField(max_length=100, blank=True)

    rating = models.PositiveSmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)],null=True,blank=True)
    total_reviews = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"Host profile of {self.user.email}"
    

class HostReview(models.Model):
    host = models.ForeignKey(HostProfile, on_delete=models.CASCADE, related_name="reviews")
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.PositiveSmallIntegerField() 
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("host", "reviewer")