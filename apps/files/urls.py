from django.urls import path
from . import views

app_name = 'files'

urlpatterns = [
    # File management
    path('upload/', views.FileUploadView.as_view(), name='file_upload'),
    path('', views.FileListView.as_view(), name='file_list'),
    path('<uuid:id>/', views.FileDetailView.as_view(), name='file_detail'),
    path('<uuid:file_id>/download/', views.FileDownloadView.as_view(), name='file_download'),
    path('<uuid:file_id>/download-url/', views.get_download_url, name='get_download_url'),
    
    # File sharing
    path('share/', views.FileShareView.as_view(), name='file_share'),
    path('shares/', views.FileShareListView.as_view(), name='file_share_list'),
    path('<uuid:file_id>/shares/', views.FileShareListView.as_view(), name='file_share_list_by_file'),
    
    # File comments
    path('<uuid:file_id>/comments/', views.FileCommentListView.as_view(), name='file_comment_list'),
    path('<uuid:file_id>/comments/add/', views.FileCommentView.as_view(), name='file_comment_add'),
    
    # File versions
    path('<uuid:file_id>/versions/', views.FileVersionListView.as_view(), name='file_version_list'),
    
    # Statistics and analytics
    path('stats/', views.file_stats, name='file_stats'),
    path('bulk-action/', views.bulk_file_action, name='bulk_file_action'),
    
    # Admin analytics
    path('admin/analytics/', views.AdminFileAnalyticsView.as_view(), name='admin_file_analytics'),
]