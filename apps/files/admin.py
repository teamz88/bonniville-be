from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import File, FileShare, FileComment, FileVersion


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = [
        'original_name', 'user', 'category', 'file_size_display',
        'status_badge', 'download_count', 'is_public', 'created_at'
    ]
    list_filter = [
        'category', 'status', 'file_type', 'is_public', 'is_shared',
        'created_at', 'updated_at'
    ]
    search_fields = [
        'original_name', 'description', 'user__username', 'user__email',
        'file_type', 'tags'
    ]
    readonly_fields = [
        'id', 'file_name', 'file_size', 'file_type', 'file_extension',
        'bucket_name', 'object_key', 'minio_url', 'upload_progress',
        'download_count', 'last_accessed', 'created_at', 'updated_at',
        'deleted_at', 'metadata_display', 'download_link'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('File Information', {
            'fields': (
                'id', 'user', 'original_name', 'file_name',
                'file_size', 'file_type', 'file_extension', 'category'
            )
        }),
        ('Storage Information', {
            'fields': (
                'bucket_name', 'object_key', 'minio_url', 'download_link'
            )
        }),
        ('Content', {
            'fields': ('description', 'tags', 'metadata_display')
        }),
        ('Status & Progress', {
            'fields': ('status', 'upload_progress')
        }),
        ('Access Control', {
            'fields': ('is_public', 'is_shared')
        }),
        ('Analytics', {
            'fields': ('download_count', 'last_accessed')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'deleted_at')
        }),
    )
    
    def file_size_display(self, obj):
        """Display human readable file size"""
        return obj.file_size_human
    file_size_display.short_description = 'Size'
    
    def status_badge(self, obj):
        """Display file status with color coding"""
        status_colors = {
            'uploading': '#ffc107',
            'processing': '#17a2b8',
            'completed': '#28a745',
            'failed': '#dc3545',
            'deleted': '#6c757d'
        }
        color = status_colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def metadata_display(self, obj):
        """Display metadata in a readable format"""
        if obj.metadata:
            items = []
            for key, value in obj.metadata.items():
                items.append(f"<strong>{key}:</strong> {value}")
            return format_html("<br>".join(items))
        return "No metadata"
    metadata_display.short_description = 'Metadata'
    
    def download_link(self, obj):
        """Display download link"""
        if obj.status == 'completed':
            url = reverse('admin:download_file', args=[obj.id])
            return format_html(
                '<a href="{}" target="_blank">Download File</a>',
                url
            )
        return "File not available"
    download_link.short_description = 'Download'
    
    actions = ['mark_as_public', 'mark_as_private', 'soft_delete_files']
    
    def mark_as_public(self, request, queryset):
        """Mark selected files as public"""
        updated = queryset.update(is_public=True)
        self.message_user(
            request, 
            f'{updated} file(s) marked as public successfully.'
        )
    mark_as_public.short_description = 'Mark selected files as public'
    
    def mark_as_private(self, request, queryset):
        """Mark selected files as private"""
        updated = queryset.update(is_public=False)
        self.message_user(
            request, 
            f'{updated} file(s) marked as private successfully.'
        )
    mark_as_private.short_description = 'Mark selected files as private'
    
    def soft_delete_files(self, request, queryset):
        """Soft delete selected files"""
        count = 0
        for file_obj in queryset:
            if not file_obj.is_deleted:
                file_obj.soft_delete()
                count += 1
        
        self.message_user(
            request, 
            f'{count} file(s) moved to trash successfully.'
        )
    soft_delete_files.short_description = 'Move selected files to trash'
    
    def get_queryset(self, request):
        """Include soft deleted files in admin"""
        return super().get_queryset(request)


@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = [
        'file_name', 'shared_by', 'shared_with', 'permissions_display',
        'is_expired', 'created_at'
    ]
    list_filter = [
        'can_download', 'can_view', 'can_comment', 'created_at',
        'expires_at'
    ]
    search_fields = [
        'file__original_name', 'shared_by__username', 'shared_with__username',
        'shared_by__email', 'shared_with__email'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at', 'is_expired']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Share Information', {
            'fields': ('id', 'file', 'shared_by', 'shared_with')
        }),
        ('Permissions', {
            'fields': ('can_download', 'can_view', 'can_comment')
        }),
        ('Expiration', {
            'fields': ('expires_at', 'is_expired')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def file_name(self, obj):
        """Display file name"""
        return obj.file.original_name
    file_name.short_description = 'File'
    
    def permissions_display(self, obj):
        """Display permissions as badges"""
        permissions = []
        if obj.can_view:
            permissions.append('<span style="color: #28a745;">👁 View</span>')
        if obj.can_download:
            permissions.append('<span style="color: #007bff;">⬇ Download</span>')
        if obj.can_comment:
            permissions.append('<span style="color: #ffc107;">💬 Comment</span>')
        
        return format_html(' '.join(permissions)) if permissions else 'No permissions'
    permissions_display.short_description = 'Permissions'
    
    def is_expired(self, obj):
        """Display expiration status"""
        if obj.expires_at:
            if obj.is_expired:
                return format_html(
                    '<span style="color: #dc3545; font-weight: bold;">❌ Expired</span>'
                )
            else:
                return format_html(
                    '<span style="color: #28a745; font-weight: bold;">✅ Active</span>'
                )
        return format_html(
            '<span style="color: #6c757d;">♾ Never expires</span>'
        )
    is_expired.short_description = 'Status'


@admin.register(FileComment)
class FileCommentAdmin(admin.ModelAdmin):
    list_display = [
        'file_name', 'user', 'content_preview', 'is_reply',
        'created_at'
    ]
    list_filter = ['created_at', 'updated_at']
    search_fields = [
        'content', 'file__original_name', 'user__username',
        'user__email'
    ]
    readonly_fields = ['id', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Comment Information', {
            'fields': ('id', 'file', 'user', 'parent')
        }),
        ('Content', {
            'fields': ('content',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def file_name(self, obj):
        """Display file name"""
        return obj.file.original_name
    file_name.short_description = 'File'
    
    def content_preview(self, obj):
        """Display truncated content"""
        if len(obj.content) > 50:
            return obj.content[:50] + '...'
        return obj.content
    content_preview.short_description = 'Content'
    
    def is_reply(self, obj):
        """Display if comment is a reply"""
        if obj.parent:
            return format_html(
                '<span style="color: #007bff;">↳ Reply</span>'
            )
        return format_html(
            '<span style="color: #28a745;">💬 Comment</span>'
        )
    is_reply.short_description = 'Type'


@admin.register(FileVersion)
class FileVersionAdmin(admin.ModelAdmin):
    list_display = [
        'file_name', 'version_number', 'uploaded_by',
        'file_size_display', 'created_at'
    ]
    list_filter = ['created_at']
    search_fields = [
        'file__original_name', 'file_name', 'uploaded_by__username',
        'change_description'
    ]
    readonly_fields = [
        'id', 'file', 'version_number', 'file_name', 'file_size',
        'object_key', 'uploaded_by', 'created_at'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Version Information', {
            'fields': (
                'id', 'file', 'version_number', 'file_name',
                'file_size', 'object_key'
            )
        }),
        ('Upload Information', {
            'fields': ('uploaded_by', 'change_description')
        }),
        ('Timestamps', {
            'fields': ('created_at',)
        }),
    )
    
    def file_name(self, obj):
        """Display original file name"""
        return obj.file.original_name
    file_name.short_description = 'Original File'
    
    def file_size_display(self, obj):
        """Display human readable file size"""
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    file_size_display.short_description = 'Size'
    
    def has_add_permission(self, request):
        """Disable manual version creation"""
        return False