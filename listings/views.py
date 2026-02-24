from django.shortcuts import render
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema

from .models import *
from .serializers import *

# Create your views here.
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework import status
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser

from listings.filters import ListingFilter


class ListingViewSet(ModelViewSet):

    queryset = Listing.objects.select_related("host").prefetch_related(
        "images",
        "amenities__category"
    )

    permission_classes = [IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_class = ListingFilter

    def get_serializer_class(self):
        if self.action == "list":
            return ListingListSerializer

        return ListingDetailSerializer

    def perform_create(self, serializer):
        serializer.save(
            host=self.request.user)

@action(

    detail=True,
    methods=["POST"],
    permission_classes=[IsAuthenticated],
    parser_classes=[MultiPartParser, FormParser]

)

def upload_images(self, request, pk=None):

    listing = self.get_object()
    if listing.host != request.user:
        return Response(
            {"error": "Not your listing"},
            status=403
        )

    files = request.FILES.getlist(
        "images"
    )


    images = []
    for index, file in enumerate(files):
        image = ListingImage.objects.create(
            listing=listing,
            image=file,
            is_primary=(
                index == 0
                and listing.images.count() == 0
            )
        )


        images.append(
            ListingImageSerializer(
                image
            ).data
        )

    return Response(
        images,
        status=201
    )

class ListingImageViewSet(ModelViewSet):

    queryset = ListingImage.objects.all()
    serializer_class = ListingImageSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    parser_classes = (MultiPartParser, FormParser)


class AmenityViewSet(ModelViewSet):
    queryset = Amenity.objects.all()
    serializer_class = AmenitySerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)


class AmenityCategoryViewSet(ModelViewSet):

    queryset = AmenityCategory.objects.all()
    serializer_class = AmenityCategorySerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)