from datetime import timedelta
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError


# =========================
# Amenity Category
# =========================

class AmenityCategory(models.Model):

    CATEGORY_CHOICES = [
        ("popular", "Popular"),
        ("amenities", "Comodidades"),
        ("features", "Características"),
    ]

    name = models.CharField(max_length=50, choices=CATEGORY_CHOICES, unique=True)

    def __str__(self):
        return self.get_name_display()


# =========================
# Amenity
# =========================

class Amenity(models.Model):

    category = models.ForeignKey(AmenityCategory,on_delete=models.CASCADE,related_name="amenities")

    name = models.CharField(max_length=100)

    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("category", "name")

    def __str__(self):
        return self.name


# =========================
# Listing
# =========================

class Listing(models.Model):

    host = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name="listings")
    amenities = models.ManyToManyField(Amenity,related_name="listings",blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField()

    PROPERTY_TYPES = [
        ("apartment", "Apartment"),
        ("house", "House"),
    ]
    property_type = models.CharField(max_length=20,choices=PROPERTY_TYPES)

    STATUS_CHOICES = [
    ("draft", "Draft"),
    ("published", "Published"),
    ("unpublished", "Unpublished"),
]

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="draft"
    )

    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    address = models.CharField(max_length=255)
    latitude = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    base_price = models.DecimalField(max_digits=10, decimal_places=2)
    guests = models.PositiveIntegerField()
    max_guests = models.PositiveIntegerField()
    bedrooms = models.PositiveIntegerField()
    bathrooms = models.PositiveIntegerField()
    cleaning_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    service_fee_percent = models.DecimalField(max_digits=5, decimal_places=2, default=10)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    rating = models.DecimalField(
    max_digits=3,
    decimal_places=2,
    default=0
    )

    total_reviews = models.PositiveIntegerField(default=0)

    class Meta:

        indexes = [
        models.Index(fields=["city"]),
        models.Index(fields=["country"]),
        models.Index(fields=["latitude", "longitude"]),
        models.Index(fields=["base_price"]),
    ]

    def __str__(self):
        return self.title

    @property
    def cover_image(self):
        primary = self.images.filter(is_primary=True).first()
        if primary:

            return primary.image.url

        image = self.images.first()
        return image.image.url if image else None


    def is_available(self, start_date, end_date):

        blocked = self.blocked_dates.filter(
        start_date__lt=end_date,
        end_date__gt=start_date
        ).exists()
        return not blocked

    def get_price(self, date):

        if hasattr(self, "season"):
            if self.season.start_date <= date <= self.season.end_date:
                return self.season.seasonal_price

        return self.base_price

    @property
    def is_published(self):

        return self.status == "published" and self.is_active

    @property
    def total_images(self):

        return self.images.count()

    def get_total_price(self, start_date, end_date):

        total = 0
        current = start_date

        while current < end_date:
            total += self.get_price(current)
            current += timedelta(days=1)

        return total

    
    def update_rating(self):

        stats = self.reviews.aggregate(

            avg=models.Avg("rating"),
            count=models.Count("id")

        )

        self.rating = stats["avg"] or 0

        self.total_reviews = stats["count"]

        self.save()

    def clean(self):

        errors = {}
        if not hasattr(self.host, "host_profile"):
            raise ValidationError("User does not have a host profile")


        if not self.host.host_profile.is_host:
            raise ValidationError("User is not a host")

        # latitude
        if not (-90 <= self.latitude <= 90):
            errors["latitude"] = "Invalid latitude"

        # longitude

        if not (-180 <= self.longitude <= 180):
            errors["longitude"] = "Invalid longitude"

        # guests

        if self.max_guests < self.guests:
            errors["max_guests"] = "Max guests must be >= guests"
        if errors:

            raise ValidationError(errors)
# =========================
# Listing Image
# =========================

class ListingImage(models.Model):

    listing = models.ForeignKey(Listing,on_delete=models.CASCADE,related_name="images")
    image = models.ImageField(upload_to="listings/%Y/%m/%d/",)
    is_primary = models.BooleanField(default=False)

    def clean(self):

        if self.is_primary:
            exists = ListingImage.objects.filter(listing=self.listing,is_primary=True).exclude(id=self.id).exists()

            if exists:
                raise ValidationError(
                    "Listing already has primary image"
                )


# =========================
# Season
# =========================

class Season(models.Model):

    listing = models.OneToOneField(Listing,on_delete=models.CASCADE,related_name="season")
    start_date = models.DateField()
    end_date = models.DateField()
    seasonal_price = models.DecimalField(max_digits=10, decimal_places=2)

    def clean(self):
        if self.start_date >= self.end_date:
            raise ValidationError("End date must be after start date")


# =========================
# Blocked Dates
# =========================

class BlockedDate(models.Model):

    listing = models.ForeignKey(Listing,on_delete=models.CASCADE,related_name="blocked_dates")
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.CharField(max_length=20,
        choices=[
            ("manual", "Manual"),
            ("booking", "Booking"),
        ]
    )
    
    def clean(self):
        if self.start_date >= self.end_date:
            raise ValidationError(
                "End date must be after start date"
            )
