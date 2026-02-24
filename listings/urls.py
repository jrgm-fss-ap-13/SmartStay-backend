from rest_framework.routers import DefaultRouter

from .views import (
    AmenityCategoryViewSet,
    ListingViewSet,
    ListingImageViewSet,
    AmenityViewSet
)

router = DefaultRouter()

router.register("listings", ListingViewSet)
router.register("images", ListingImageViewSet)
router.register("amenities", AmenityViewSet)
router.register("amenity-categories",AmenityCategoryViewSet,basename="amenity-categories")


urlpatterns = router.urls