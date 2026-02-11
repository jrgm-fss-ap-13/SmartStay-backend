from rest_framework.views import exception_handler
from rest_framework.response import Response

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        return Response({
            "success": False,
            "errors": response.data,
            "status_code": response.status_code
        }, status=response.status_code)

    return Response({
        "success": False,
        "errors": "Server error",
        "status_code": 500
    }, status=500)