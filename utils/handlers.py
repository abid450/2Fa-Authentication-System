from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import PermissionDenied
from django.http import Http404
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    কাস্টম এক্সেপশন হ্যান্ডলার
    """
    # REST framework এর ডিফল্ট হ্যান্ডলার কল
    response = exception_handler(exc, context)
    
    request = context.get('request')
    view = context.get('view')
    
    # এক্সেপশন লগ করা
    logger.error(
        f"Exception: {exc.__class__.__name__} - {str(exc)} - "
        f"View: {view.__class__.__name__ if view else 'Unknown'} - "
        f"Path: {request.path if request else 'Unknown'}"
    )
    
    if response is not None:
        # কাস্টম এরর রেসপন্স ফরম্যাট
        custom_response = {
            'status': 'error',
            'message': response.data.get('detail', str(exc)) if isinstance(response.data, dict) else str(exc),
            'code': response.status_code
        }
        
        # ভ্যালিডেশন এরর থাকলে
        if response.status_code == 400 and isinstance(response.data, dict):
            custom_response['errors'] = response.data
        
        response.data = custom_response
    
    else:
        # আনহ্যান্ডেলড এক্সেপশন
        if isinstance(exc, Http404):
            response = Response({
                'status': 'error',
                'message': 'পাতা পাওয়া যায়নি',
                'code': 404
            }, status=status.HTTP_404_NOT_FOUND)
        
        elif isinstance(exc, PermissionDenied):
            response = Response({
                'status': 'error',
                'message': 'অনুমতি নেই',
                'code': 403
            }, status=status.HTTP_403_FORBIDDEN)
        
        else:
            # প্রোডাকশনে ৫০০ এরর না দেখিয়ে জেনেরিক মেসেজ দেখানো
            if not getattr(context.get('request'), 'debug', False):
                response = Response({
                    'status': 'error',
                    'message': 'সার্ভারে সমস্যা হয়েছে',
                    'code': 500
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return response