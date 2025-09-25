import os
import uuid
import mimetypes
import shutil
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urljoin
from pathlib import Path

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils import timezone
from django.http import FileResponse, Http404
import logging

from .models import File, FileCategory, FileStatus

logger = logging.getLogger(__name__)


class LocalFileService:
    """Service for local file operations"""
    
    def __init__(self):
        self.storage_root = getattr(settings, 'FILE_STORAGE_ROOT', str(settings.BASE_DIR / 'media' / 'uploads'))
        self._ensure_storage_exists()
    
    def _ensure_storage_exists(self):
        """Ensure the storage directory exists"""
        try:
            Path(self.storage_root).mkdir(parents=True, exist_ok=True)
            logger.info(f"Storage directory ready: {self.storage_root}")
        except Exception as e:
            logger.error(f"Error creating storage directory: {e}")
            raise
    
    def generate_file_path(self, user_id: int, filename: str) -> str:
        """Generate unique file path for local storage"""
        # Generate unique identifier
        unique_id = str(uuid.uuid4())[:8]
        
        # Clean filename
        name, ext = os.path.splitext(filename)
        clean_name = "".join(c for c in name if c.isalnum() or c in (' ', '-', '_')).strip()
        clean_filename = f"{clean_name}_{unique_id}{ext}"
        
        # Store directly in uploads directory without user folders
        return clean_filename
    
    def upload_file(
        self, 
        uploaded_file: UploadedFile, 
        file_path: str,
        content_type: Optional[str] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Upload file to local storage"""
        try:
            # Determine content type
            if not content_type:
                content_type, _ = mimetypes.guess_type(uploaded_file.name)
                if not content_type:
                    content_type = 'application/octet-stream'
            
            # Create full file path
            full_path = os.path.join(self.storage_root, file_path)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            # Save file
            with open(full_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            # Get file metadata
            file_stat = os.stat(full_path)
            metadata = {
                'content_type': content_type,
                'size': file_stat.st_size,
                'created_at': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                'modified_at': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            }
            
            logger.info(f"Successfully uploaded file: {file_path}")
            return True, "File uploaded successfully", metadata
            
        except Exception as e:
            error_msg = f"File upload error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def download_file(self, file_path: str) -> Tuple[bool, Any, str]:
        """Download file from local storage"""
        try:
            full_path = os.path.join(self.storage_root, file_path)
            
            if not os.path.exists(full_path):
                return False, None, "File not found"
            
            # Return file response
            response = open(full_path, 'rb')
            return True, response, "File retrieved successfully"
            
        except Exception as e:
            error_msg = f"File download error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def delete_file(self, file_path: str) -> Tuple[bool, str]:
        """Delete file from local storage"""
        try:
            full_path = os.path.join(self.storage_root, file_path)
            
            if not os.path.exists(full_path):
                return True, "File already deleted or not found"
            
            os.remove(full_path)
            
            # Try to remove empty directories
            try:
                dir_path = os.path.dirname(full_path)
                while dir_path != self.storage_root:
                    if not os.listdir(dir_path):  # Directory is empty
                        os.rmdir(dir_path)
                        dir_path = os.path.dirname(dir_path)
                    else:
                        break
            except OSError:
                pass  # Directory not empty or other issue
            
            logger.info(f"Successfully deleted file: {file_path}")
            return True, "File deleted successfully"
            
        except Exception as e:
            error_msg = f"File delete error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_file_url(self, file_path: str) -> Tuple[bool, Optional[str], str]:
        """Generate URL for file access (for local storage, returns relative path)"""
        try:
            full_path = os.path.join(self.storage_root, file_path)
            
            if not os.path.exists(full_path):
                return False, None, "File not found"
            
            # For local storage, return the media URL path
            from django.conf import settings
            media_url = getattr(settings, 'MEDIA_URL', '/media/')
            file_url = f"{media_url}uploads/{file_path}"
            
            return True, file_url, "File URL generated successfully"
            
        except Exception as e:
            error_msg = f"File URL generation error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def get_file_info(self, file_path: str) -> Tuple[bool, Dict[str, Any], str]:
        """Get file information from local storage"""
        try:
            full_path = os.path.join(self.storage_root, file_path)
            
            if not os.path.exists(full_path):
                return False, {}, "File not found"
            
            file_stat = os.stat(full_path)
            content_type, _ = mimetypes.guess_type(full_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            info = {
                'size': file_stat.st_size,
                'content_type': content_type,
                'last_modified': datetime.fromtimestamp(file_stat.st_mtime),
                'created_at': datetime.fromtimestamp(file_stat.st_ctime),
                'file_path': file_path
            }
            
            return True, info, "File info retrieved successfully"
            
        except Exception as e:
            error_msg = f"File info error: {str(e)}"
            logger.error(error_msg)
            return False, {}, error_msg
    
    def copy_file(
        self, 
        source_file_path: str, 
        dest_file_path: str
    ) -> Tuple[bool, str]:
        """Copy file within local storage"""
        try:
            source_full_path = os.path.join(self.storage_root, source_file_path)
            dest_full_path = os.path.join(self.storage_root, dest_file_path)
            
            if not os.path.exists(source_full_path):
                return False, "Source file not found"
            
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dest_full_path), exist_ok=True)
            
            # Copy file
            shutil.copy2(source_full_path, dest_full_path)
            
            logger.info(f"Successfully copied file from {source_file_path} to {dest_file_path}")
            return True, "File copied successfully"
            
        except Exception as e:
            error_msg = f"File copy error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg


class FileService:
    """Service for handling file operations"""
    
    def __init__(self):
        self.storage_service = LocalFileService()
    
    def upload_file(
        self, 
        user, 
        uploaded_file: UploadedFile, 
        description: str = "",
        tags: list = None,
        is_public: bool = False
    ) -> Tuple[bool, File, str]:
        """Upload and process file"""
        if tags is None:
            tags = []
        
        try:
            # Generate file path
            file_path = self.storage_service.generate_file_path(
                user.id, uploaded_file.name
            )
            
            # Determine file category
            content_type, _ = mimetypes.guess_type(uploaded_file.name)
            if not content_type:
                content_type = 'application/octet-stream'
            
            # Create file record
            file_obj = File.objects.create(
                user=user,
                original_name=uploaded_file.name,
                file_name=os.path.basename(file_path),
                file_size=uploaded_file.size,
                file_type=content_type,
                file_extension=os.path.splitext(uploaded_file.name)[1].lower(),
                category=self._get_category_from_mime_type(content_type),
                bucket_name="",
                object_key=file_path,
                description=description,
                tags=tags,
                is_public=is_public,
                status=FileStatus.UPLOADING
            )
            
            # Upload to local storage
            success, message, metadata = self.storage_service.upload_file(
                uploaded_file, file_path, content_type
            )
            
            if success:
                # Update file record
                file_obj.status = FileStatus.COMPLETED
                file_obj.upload_progress = 100
                file_obj.metadata = metadata
                file_obj.save()
                
                logger.info(f"File uploaded successfully: {file_obj.id}")
                return True, file_obj, "File uploaded successfully"
            else:
                # Mark as failed
                file_obj.status = FileStatus.FAILED
                file_obj.save()
                return False, file_obj, message
                
        except Exception as e:
            error_msg = f"File upload error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg

    def upload_public_file(
        self, 
        uploaded_file: UploadedFile, 
        description: str = "",
        tags: list = None
    ) -> Tuple[bool, File, str]:
        """Upload file for public/anonymous access"""
        from django.contrib.auth import get_user_model
        
        if tags is None:
            tags = []
        
        try:
            User = get_user_model()
            
            # Get or create a system user for anonymous uploads
            system_user, created = User.objects.get_or_create(
                username='system_anonymous',
                defaults={
                    'email': 'system@bonniville.com',
                    'first_name': 'System',
                    'last_name': 'Anonymous',
                    'is_active': True,
                    'role': 'user'
                }
            )
            
            # Generate file path using system user ID
            file_path = self.storage_service.generate_file_path(
                system_user.id, uploaded_file.name
            )
            
            # Determine file category
            content_type, _ = mimetypes.guess_type(uploaded_file.name)
            if not content_type:
                content_type = 'application/octet-stream'
            
            # Create file record - always public for anonymous uploads
            file_obj = File.objects.create(
                user=system_user,
                original_name=uploaded_file.name,
                file_name=os.path.basename(file_path),
                file_size=uploaded_file.size,
                file_type=content_type,
                file_extension=os.path.splitext(uploaded_file.name)[1].lower(),
                category=self._get_category_from_mime_type(content_type),
                bucket_name="",
                object_key=file_path,
                description=description,
                tags=tags,
                is_public=True,  # Always public for anonymous uploads
                status=FileStatus.UPLOADING
            )
            
            # Upload to local storage
            success, message, metadata = self.storage_service.upload_file(
                uploaded_file, file_path, content_type
            )
            
            if success:
                # Update file record
                file_obj.status = FileStatus.COMPLETED
                file_obj.upload_progress = 100
                file_obj.metadata = metadata
                file_obj.save()
                
                logger.info(f"Public file uploaded successfully: {file_obj.id}")
                return True, file_obj, "File uploaded successfully"
            else:
                # Mark as failed
                file_obj.status = FileStatus.FAILED
                file_obj.save()
                return False, file_obj, message
                
        except Exception as e:
            error_msg = f"Public file upload error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg

    def download_file(self, file_obj: File, user) -> Tuple[bool, Any, str]:
        """Download file with permission check"""
        try:
            # Check permissions
            if not self._can_access_file(file_obj, user):
                return False, None, "Permission denied"
            
            # Download from local storage
            success, response, message = self.storage_service.download_file(
                file_obj.object_key
            )
            
            if success:
                # Update download count
                file_obj.increment_download_count()
                return True, response, message
            else:
                return False, None, message
                
        except Exception as e:
            error_msg = f"File download error: {str(e)}"
            logger.error(error_msg)
            return False, None, error_msg
    
    def delete_file(self, file_obj: File, user, hard_delete: bool = False) -> Tuple[bool, str]:
        """Delete file with permission check"""
        try:
            # Check permissions
            if not self._can_modify_file(file_obj, user):
                return False, "Permission denied"
            
            if hard_delete:
                # Delete from local storage
                success, message = self.storage_service.delete_file(file_obj.object_key)
                if success:
                    # Delete from database
                    file_obj.delete()
                    return True, "File permanently deleted"
                else:
                    return False, f"Failed to delete from storage: {message}"
            else:
                # Soft delete
                file_obj.soft_delete()
                return True, "File moved to trash"
                
        except Exception as e:
            error_msg = f"File delete error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_download_url(
        self, 
        file_obj: File, 
        user, 
        expires: timedelta = timedelta(hours=1)
    ) -> Tuple[bool, str, str]:
        """Get download URL for local file"""
        try:
            # Check permissions
            if not self._can_access_file(file_obj, user):
                return False, "", "Permission denied"
            
            # Generate file URL
            success, url, message = self.storage_service.get_file_url(
                file_obj.object_key
            )
            
            if success:
                # Update last accessed
                file_obj.last_accessed = timezone.now()
                file_obj.save(update_fields=['last_accessed'])
            
            return success, url, message
            
        except Exception as e:
            error_msg = f"Get download URL error: {str(e)}"
            logger.error(error_msg)
            return False, "", error_msg
    
    def _can_access_file(self, file_obj: File, user) -> bool:
        """Check if user can access file"""
        # Admin can access all files
        if user.is_admin:
            return True
        
        # Owner can access their files
        if file_obj.user == user:
            return True
        
        # Check if file is public
        if file_obj.is_public:
            return True
        
        # Check if file is shared with user
        if file_obj.shares.filter(
            shared_with=user,
            can_view=True
        ).exists():
            return True
        
        return False
    
    def _can_modify_file(self, file_obj: File, user) -> bool:
        """Check if user can modify file"""
        # Admin can modify all files
        if user.is_admin:
            return True
        
        # Owner can modify their files
        if file_obj.user == user:
            return True
        
        return False
    
    def _get_category_from_mime_type(self, mime_type: str) -> str:
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
    
    def get_user_storage_stats(self, user) -> Dict[str, Any]:
        """Get user storage statistics"""
        from django.db.models import Count
        from django.db.models.functions import TruncMonth
        
        files = File.objects.filter(user=user, deleted_at__isnull=True)
        
        total_files = files.count()
        total_size = sum(f.file_size for f in files)
        
        # Files by category
        category_stats = {}
        for category in FileCategory.choices:
            count = files.filter(category=category[0]).count()
            if count > 0:
                category_stats[category[1]] = count
        
        # Files by month (last 12 months)
        files_by_month = {}
        monthly_stats = files.annotate(
            month=TruncMonth('created_at')
        ).values('month').annotate(
            count=Count('id')
        ).order_by('-month')[:12]
        
        for stat in monthly_stats:
            month_key = stat['month'].strftime('%Y-%m')
            files_by_month[month_key] = stat['count']
        
        # Recent uploads (last 30 days)
        recent_date = timezone.now() - timedelta(days=30)
        recent_files_queryset = files.filter(created_at__gte=recent_date).order_by('-created_at')[:10]
        recent_uploads_list = [
            {
                'name': f.original_name,
                'size': self._format_file_size(f.file_size),
                'created_at': f.created_at.isoformat(),
                'file_type': f.file_type
            }
            for f in recent_files_queryset
        ]
        
        # Most downloaded files
        most_downloaded = files.filter(
            download_count__gt=0
        ).order_by('-download_count')[:5]
        
        # Storage usage percentage (assuming 1GB limit per user)
        storage_limit = 1024 * 1024 * 1024  # 1GB in bytes
        storage_usage_percentage = (total_size / storage_limit) * 100 if storage_limit > 0 else 0
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'total_size_human': self._format_file_size(total_size),
            'files_by_category': category_stats,
            'files_by_month': files_by_month,
            'recent_uploads': recent_uploads_list,
            'most_downloaded': [
                {
                    'name': f.original_name,
                    'downloads': f.download_count,
                    'size': self._format_file_size(f.file_size)
                }
                for f in most_downloaded
            ],
            'storage_usage_percentage': storage_usage_percentage
        }
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"