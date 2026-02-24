from rest_framework import serializers
from .models import AmenityCategory, Listing, ListingImage, Amenity


# ----------------------------
# LISTING IMAGE SERIALIZER
# ----------------------------


class AmenityCategorySerializer(serializers.ModelSerializer):

    display_name = serializers.CharField(
        source="get_name_display",
        read_only=True
    )

    class Meta:

        model = AmenityCategory

        fields = [

            "id",
            "name",
            "display_name"

        ]

class AmenitySerializer(serializers.ModelSerializer):

    category = AmenityCategorySerializer(
        read_only=True
    )

    class Meta:

        model = Amenity

        fields = [

            "id",
            "name",
            "category"
        ]



class ListingImageSerializer(serializers.ModelSerializer):

    image = serializers.ImageField()

    class Meta:

        model = ListingImage

        fields = [
            "id",
            "image",
            "listing",
        ]

        read_only_fields = (
            "id",
            "listing",
        )

class ListingSerializer(serializers.ModelSerializer):

    host = serializers.ReadOnlyField(source="host.id")

    images = ListingImageSerializer(
        many=True,
        read_only=True,
        source="images.all"
    )

    cover_image = serializers.SerializerMethodField()
    amenities = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Amenity.objects.all(),
        required=False
    )


    class Meta:

        model = Listing

        fields = "__all__"

        read_only_fields = (

            "id",
            "host",
            "rating",
            "total_reviews",
            "created_at",
            "updated_at",

        )


    def validate(self, data):
        amenities = data.pop("amenities", [])
        instance = Listing(
            host=self.context["request"].user,
            **data
        )
        instance.full_clean()
        data["amenities"] = amenities
        return data



    def create(self, validated_data):
        amenities = validated_data.pop("amenities", [])
        listing = Listing.objects.create(**validated_data)
        listing.amenities.set(amenities)

        return listing


    # ✅ FIX UPDATE
    def update(self, instance, validated_data):

        amenities = validated_data.pop("amenities", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        if amenities is not None:
            instance.amenities.set(amenities)

        return instance


    def get_cover_image(self, obj):
        first_image = obj.images.first()
        if first_image:
            return first_image.image.url

        return None

class ListingDetailSerializer(serializers.ModelSerializer):

    host = serializers.ReadOnlyField(
        source="host.id"
    )


    images = ListingImageSerializer(
        many=True,
        read_only=True
    )

    cover_image = serializers.ReadOnlyField()
    amenities = AmenitySerializer(many=True,read_only=True)
    amenities_ids = serializers.PrimaryKeyRelatedField(many=True,queryset=Amenity.objects.all(),write_only=True,
    source="amenities")


    class Meta:

        model = Listing
        fields = "__all__"

        read_only_fields = [
            "id",
            "host",
            "rating",
            "total_reviews",
            "created_at",
            "updated_at"
        ]


    def create(self, validated_data):
        amenities = validated_data.pop("amenities",[])
        listing = Listing.objects.create(**validated_data)
        listing.amenities.set(amenities)

        return listing


    def update(self, instance, validated_data):
        amenities = validated_data.pop("amenities",None)

        for attr, value in validated_data.items():

            setattr(instance,attr,value)
        instance.save()


        if amenities is not None:
            instance.amenities.set(amenities)

        return instance



class ListingListSerializer(serializers.ModelSerializer):

    cover_image = serializers.ReadOnlyField()

    class Meta:

        model = Listing
        fields = [
            "id",
            "title",
            "city",
            "country",
            "base_price",
            "rating",
            "cover_image"
        ]

    def get_cover_image(self, obj):
        first_image = obj.images.first()

        if first_image:
            return first_image.image.url

        return None
