from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'analytics'

# Router for ViewSets (if we had any)
router = DefaultRouter()

urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Analytics Events
    path('events/', views.AnalyticsEventListView.as_view(), name='event-list'),
    path('events/track/', views.track_event, name='track-event'),
    
    # User Activity
    path('activity/', views.UserActivityListView.as_view(), name='activity-list'),
    path('activity/stats/', views.user_activity_stats, name='activity-stats'),
    
    # System Metrics (Admin only)
    path('metrics/', views.SystemMetricsListView.as_view(), name='metrics-list'),
    path('metrics/generate/', views.generate_system_metrics, name='generate-metrics'),
    path('health/', views.system_health, name='system-health'),
    
    # Reports
    path('reports/', views.ReportListCreateView.as_view(), name='report-list'),
    path('reports/<int:pk>/', views.ReportDetailView.as_view(), name='report-detail'),
    path('reports/<int:pk>/download/', views.ReportDownloadView.as_view(), name='report-download'),
    
    # Feature Usage (Admin only)
    path('features/', views.FeatureUsageListView.as_view(), name='feature-usage-list'),
    
    # Error Logs (Admin only)
    path('errors/', views.ErrorLogListView.as_view(), name='error-list'),
    path('errors/<int:pk>/', views.ErrorLogDetailView.as_view(), name='error-detail'),
    path('errors/log/', views.log_error, name='log-error'),
    path('errors/stats/', views.error_stats, name='error-stats'),
    
    # Dashboard
    path('dashboard/', views.dashboard_stats, name='dashboard-stats'),
    path('subscription-stats/', views.subscription_stats, name='subscription-stats'),
    path('payment-stats/', views.payment_stats, name='payment-stats'),
    path('user-dashboard-stats/', views.user_dashboard_stats, name='user-dashboard-stats'),
    path('users-list-stats/', views.users_list_stats, name='users-list-stats'),
]