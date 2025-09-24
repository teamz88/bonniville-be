from django.urls import path
from . import views
from . import folder_views

app_name = 'files'

urlpatterns = [
    # File management
    path('upload/', views.FileUploadView.as_view(), name='file_upload'),
    path('', views.FileListView.as_view(), name='file_list'),
    path('<uuid:id>/', views.FileDetailView.as_view(), name='file_detail'),
    path('<uuid:file_id>/download/', views.FileDownloadView.as_view(), name='file_download'),
    path('<uuid:file_id>/download-url/', views.get_download_url, name='get_download_url'),
    path('<uuid:file_id>/move/', views.move_file_to_folder, name='move_file_to_folder'),
    
    # File sharing
    path('share/', views.FileShareView.as_view(), name='file_share'),
    path('shares/', views.FileShareListView.as_view(), name='file_share_list'),
    path('<uuid:file_id>/shares/', views.FileShareListView.as_view(), name='file_share_list_by_file'),
    
    # File comments
    path('<uuid:file_id>/comments/', views.FileCommentListView.as_view(), name='file_comment_list'),
    path('<uuid:file_id>/comments/add/', views.FileCommentView.as_view(), name='file_comment_add'),
    
    # File versions
    path('<uuid:file_id>/versions/', views.FileVersionListView.as_view(), name='file_version_list'),
    
    # Folder management
    path('folders/', folder_views.FolderListCreateView.as_view(), name='folder_list_create'),
    path('folders/<uuid:id>/', folder_views.FolderDetailView.as_view(), name='folder_detail'),
    path('folders/tree/', folder_views.FolderTreeView.as_view(), name='folder_tree'),
    path('folders/<uuid:folder_id>/move/', folder_views.MoveFolderView.as_view(), name='move_folder'),
    path('folders/<uuid:folder_id>/restore/', folder_views.restore_folder, name='restore_folder'),
    path('folders/<uuid:folder_id>/contents/', folder_views.folder_contents, name='folder_contents'),
    path('folders/<uuid:folder_id>/breadcrumbs/', folder_views.folder_breadcrumbs, name='folder_breadcrumbs'),
    
    # Statistics and analytics
    path('stats/', views.file_stats, name='file_stats'),
    path('bulk-action/', views.bulk_file_action, name='bulk_file_action'),
    
    # Admin-only endpoints
    path('admin/<uuid:file_id>/delete/', views.admin_delete_file, name='admin_delete_file'),
    path('admin/bulk-delete/', views.admin_bulk_delete, name='admin_bulk_delete'),
    
    # Admin analytics
    path('admin/analytics/', views.AdminFileAnalyticsView.as_view(), name='admin_file_analytics'),
]