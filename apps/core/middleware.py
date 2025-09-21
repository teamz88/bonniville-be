import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from apps.core.notifications import notification_service

logger = logging.getLogger(__name__)

class ErrorNotificationMiddleware(MiddlewareMixin):
    """
    Middleware to catch and notify about unhandled errors
    """
    
    def process_exception(self, request, exception):
        """
        Process unhandled exceptions and send notifications
        """
        # Collect error information
        error_info = {
            'error_type': type(exception).__name__,
            'error_message': str(exception),
            'request_path': request.path,
            'request_method': request.method,
            'user_ip': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown'),
            'timestamp': timezone.now().isoformat()
        }
        
        # Add user information
        if hasattr(request, 'user') and request.user.is_authenticated:
            error_info['user_email'] = request.user.email
            error_info['user_id'] = request.user.id
        
        # Send notification
        try:
            error_message = f"Unhandled Exception: {error_info['error_type']}\n"
            error_message += f"Message: {error_info['error_message']}\n"
            error_message += f"Path: {error_info['request_method']} {error_info['request_path']}\n"
            error_message += f"IP: {error_info['user_ip']}\n"
            error_message += f"User Agent: {error_info['user_agent'][:100]}\n"
            error_message += f"Time: {error_info['timestamp']}"
            
            user_info = {}
            if 'user_email' in error_info:
                user_info['email'] = error_info['user_email']
                user_info['user_id'] = error_info['user_id']
            
            notification_service.send_error_notification(
                error_message,
                "Unhandled Server Exception",
                user_info if user_info else None
            )
            
            # Log the error
            logger.error(f"Unhandled exception: {str(exception)}", exc_info=True)
            
        except Exception as notification_error:
            # If notification sending fails, log it
            logger.error(f"Failed to send error notification: {notification_error}")
        
        # Return None to let Django handle the exception normally
        return None
    
    def get_client_ip(self, request):
        """
        Get client IP address from request
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip