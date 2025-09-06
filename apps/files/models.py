import os
import uuid
from django.db import models
from django.conf import settings
from django.core.validators import FileExtensionValidator
from django.utils import timezone


class FileCategory(models.TextChoices):
    """File category choices"""
    DOCUMENT = 'document', 'Document'
    IMAGE = 'image', 'Image'
    VIDEO = 'video', 'Video'
    AUDIO = 'audio', 'Audio'
    ARCHIVE = 'archive', 'Archive'
    OTHER = 'other', 'Other'


class FileStatus(models.TextChoices):
    """File processing status choices"""
    UPLOADING = 'uploading', 'Uploading'
    PROCESSING = 'processing', 'Processing'
    COMPLETED = 'completed', 'Completed'
    FAILED = 'failed', 'Failed'
    DELETED = 'deleted', 'Deleted'


class File(models.Model):
    """Model for file management with local storage"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='files'
    )
    
    # File information
    original_name = models.CharField(max_length=255)
    file_name = models.CharField(max_length=255)  # Stored filename in local storage
    file_size = models.BigIntegerField()  # Size in bytes
    file_type = models.CharField(max_length=100)  # MIME type
    file_extension = models.CharField(max_length=10)
    category = models.CharField(
        max_length=20,
        choices=FileCategory.choices,
        default=FileCategory.OTHER
    )
    
    # Local storage information
    bucket_name = models.CharField(max_length=100, default='', blank=True)  # Legacy field, kept for compatibility
    object_key = models.CharField(max_length=500)  # Full path in local storage
    minio_url = models.URLField(max_length=500, blank=True)  # Legacy field, kept for compatibility
    
    # File processing
    status = models.CharField(
        max_length=20,
        choices=FileStatus.choices,
        default=FileStatus.UPLOADING
    )
    upload_progress = models.IntegerField(default=0)  # 0-100
    
    # Metadata
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)  # Additional file metadata
    
    # Access control
    is_public = models.BooleanField(default=False)
    is_shared = models.BooleanField(default=False)
    shared_with = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through='FileShare',
        through_fields=('file', 'shared_with'),
        related_name='shared_files',
        blank=True
    )
    
    # Analytics
    download_count = models.IntegerField(default=0)
    last_accessed = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'files'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['category', 'created_at']),
            models.Index(fields=['file_type']),
            models.Index(fields=['is_public', 'is_shared']),
        ]
    
    def __str__(self):
        return f"{self.original_name} ({self.user.username})"
    
    @property
    def file_size_human(self):
        """Return human readable file size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} PB"
    
    @property
    def is_image(self):
        """Check if file is an image"""
        return self.category == FileCategory.IMAGE
    
    @property
    def is_document(self):
        """Check if file is a document"""
        return self.category == FileCategory.DOCUMENT
    
    @property
    def is_deleted(self):
        """Check if file is soft deleted"""
        return self.deleted_at is not None
    
    def soft_delete(self):
        """Soft delete the file"""
        self.deleted_at = timezone.now()
        self.status = FileStatus.DELETED
        self.save(update_fields=['deleted_at', 'status'])
    
    def restore(self):
        """Restore soft deleted file"""
        self.deleted_at = None
        self.status = FileStatus.COMPLETED
        self.save(update_fields=['deleted_at', 'status'])
    
    def increment_download_count(self):
        """Increment download count and update last accessed"""
        self.download_count += 1
        self.last_accessed = timezone.now()
        self.save(update_fields=['download_count', 'last_accessed'])
    
    def get_category_from_mime_type(self, mime_type):
        """Determine file category from MIME type"""
        if mime_type.startswith('image/'):
            return FileCategory.IMAGE
        elif mime_type.startswith('video/'):
            return FileCategory.VIDEO
        elif mime_type.startswith('audio/'):
            return FileCategory.AUDIO
        elif mime_type in [
            'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain', 'text/csv'
        ]:
            return FileCategory.DOCUMENT
        elif mime_type in [
            'application/zip', 'application/x-rar-compressed',
            'application/x-tar', 'application/gzip'
        ]:
            return FileCategory.ARCHIVE
        else:
            return FileCategory.OTHER


class FileShare(models.Model):
    """Model for file sharing between users"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='files_shared_by_me'
    )
    shared_with = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='files_shared_with_me'
    )
    
    # Permissions
    can_download = models.BooleanField(default=True)
    can_view = models.BooleanField(default=True)
    can_comment = models.BooleanField(default=False)
    
    # Expiration
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'file_shares'
        unique_together = ['file', 'shared_with']
        indexes = [
            models.Index(fields=['shared_by', 'created_at']),
            models.Index(fields=['shared_with', 'created_at']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.file.original_name} shared with {self.shared_with.username}"
    
    @property
    def is_expired(self):
        """Check if share has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    def is_accessible_by(self, user):
        """Check if user can access this shared file"""
        if self.is_expired:
            return False
        return self.shared_with == user or self.shared_by == user


class FileVersion(models.Model):
    """Model for file version history"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='versions')
    
    # Version information
    version_number = models.IntegerField()
    file_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField()
    object_key = models.CharField(max_length=500)
    
    # Metadata
    change_description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='file_versions'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'file_versions'
        unique_together = ['file', 'version_number']
        ordering = ['-version_number']
        indexes = [
            models.Index(fields=['file', 'version_number']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.file.original_name} v{self.version_number}"


class FileComment(models.Model):
    """Model for file comments"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='file_comments'
    )
    
    # Comment content
    content = models.TextField()
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='replies'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'file_comments'
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['file', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]
    
    def __str__(self):
        return f"Comment on {self.file.original_name} by {self.user.username}"
    
    @property
    def is_reply(self):
        """Check if this is a reply to another comment"""
        return self.parent is not None