from datetime import timedelta
from django.db.models import Q
from listings.models import Listing, BlockedDate
from bookings.models import Booking


class AvailabilityService:

    @staticmethod
    def validate_dates(check_in, check_out):
        if check_in >= check_out:
            raise ValueError("Check-out must be after check-in.")

    @staticmethod
    def is_range_blocked(listing, check_in, check_out):

        # Bloqueos manuales o por booking
        blocked = BlockedDate.objects.filter(
            listing=listing
        ).filter(
            Q(start_date__lt=check_out) &
            Q(end_date__gt=check_in)
        ).exists()

        return blocked

    @staticmethod
    def has_overlapping_booking(listing, check_in, check_out):

        overlapping = Booking.objects.filter(
            listing=listing,
            status__in=["confirmed", "pending"]
        ).filter(
            Q(check_in__lt=check_out) &
            Q(check_out__gt=check_in)
        ).exists()

        return overlapping

    @staticmethod
    def calculate_price(listing, check_in, check_out):

        nights = (check_out - check_in).days

        price_per_night = listing.base_price

        # Si existe temporada y cae dentro del rango
        if hasattr(listing, "season"):
            season = listing.season
            if check_in >= season.start_date and check_out <= season.end_date:
                price_per_night = season.seasonal_price

        subtotal = nights * price_per_night
        cleaning_fee = listing.cleaning_fee
        service_fee = subtotal * (listing.service_fee_percent / 100)

        total = subtotal + cleaning_fee + service_fee

        return {
            "nights": nights,
            "price_per_night": price_per_night,
            "subtotal": subtotal,
            "cleaning_fee": cleaning_fee,
            "service_fee": service_fee,
            "total": total
        }

    @classmethod
    def check_availability(cls, listing_id, check_in, check_out):

        listing = Listing.objects.get(id=listing_id)

        cls.validate_dates(check_in, check_out)

        if cls.is_range_blocked(listing, check_in, check_out):
            raise ValueError("Selected dates are blocked.")

        if cls.has_overlapping_booking(listing, check_in, check_out):
            raise ValueError("Listing already booked for selected dates.")

        pricing = cls.calculate_price(listing, check_in, check_out)

        return pricing
