import django_filters

from .models import Listing


class ListingFilter(django_filters.FilterSet):

    min_price = django_filters.NumberFilter(

        field_name="base_price",
        lookup_expr="gte"
    )

    max_price = django_filters.NumberFilter(
        field_name="base_price",
        lookup_expr="lte"
    )

    city = django_filters.CharFilter(
        lookup_expr="icontains"
    )

    class Meta:

        model = Listing
        fields = [
            "city",
            "country",
            "guests"
        ]