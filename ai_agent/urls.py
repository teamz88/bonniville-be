from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.utils import timezone
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


def health_check(request):
    """Simple health check endpoint for Docker"""
    return JsonResponse({'status': 'healthy', 'timestamp': timezone.now().isoformat()})

# Swagger/OpenAPI schema configuration
schema_view = get_schema_view(
    openapi.Info(
        title="AI Agent API",
        default_version='v1',
        description="AI Agent application REST API documentation",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@aiagent.local"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # Health check
    path('api/health/', health_check, name='health_check'),
    
    # Admin
    path('admin/', admin.site.urls),
    
    # API Documentation
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # API endpoints
    path('api/auth/', include('apps.authentication.urls')),
    path('api/chat/', include('apps.chat.urls')),
    path('api/files/', include('apps.files.urls')),
    path('api/analytics/', include('apps.analytics.urls')),
    path('api/core/', include('apps.core.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)