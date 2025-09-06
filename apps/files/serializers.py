from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import FileExtensionValidator
from .models import File, FileShare, FileVersion, FileComment

User = get_user_model()


class FileUploadSerializer(serializers.Serializer):
    """Serializer for file upload"""
    file = serializers.FileField(
        validators=[
            FileExtensionValidator(
                allowed_extensions=[
                    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                    'txt', 'csv', 'jpg', 'jpeg', 'png', 'gif', 'bmp',
                    'mp4', 'avi', 'mov', 'wmv', 'mp3', 'wav', 'flac',
                    'zip', 'rar', 'tar', 'gz', '7z'
                ]
            )
        ]
    )
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)
    tags = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False,
        allow_empty=True
    )
    is_public = serializers.BooleanField(default=False)
    
    def validate_file(self, value):
        """Validate file size and type"""
        # Check file size (50MB limit)
        max_size = 50 * 1024 * 1024  # 50MB
        if value.size > max_size:
            raise serializers.ValidationError(
                f"File size cannot exceed {max_size // (1024 * 1024)}MB"
            )
        
        # Check if file is not empty
        if value.size == 0:
            raise serializers.ValidationError("File cannot be empty")
        
        return value
    
    def validate_tags(self, value):
        """Validate tags"""
        if len(value) > 10:
            raise serializers.ValidationError("Maximum 10 tags allowed")
        
        for tag in value:
            if len(tag.strip()) < 2:
                raise serializers.ValidationError("Each tag must be at least 2 characters long")
        
        return [tag.strip().lower() for tag in value]


class UserBasicSerializer(serializers.ModelSerializer):
    """Basic user serializer for file sharing"""
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'full_name']
        read_only_fields = ['id', 'username', 'email', 'full_name']


class FileCommentSerializer(serializers.ModelSerializer):
    """Serializer for file comments"""
    user = UserBasicSerializer(read_only=True)
    replies = serializers.SerializerMethodField()
    
    class Meta:
        model = FileComment
        fields = [
            'id', 'content', 'user', 'parent', 'replies',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']
    
    def get_replies(self, obj):
        """Get replies to this comment"""
        if obj.replies.exists():
            return FileCommentSerializer(obj.replies.all(), many=True).data
        return []
    
    def validate_content(self, value):
        """Validate comment content"""
        if len(value.strip()) < 3:
            raise serializers.ValidationError(
                "Comment must be at least 3 characters long"
            )
        return value.strip()


class FileVersionSerializer(serializers.ModelSerializer):
    """Serializer for file versions"""
    uploaded_by = UserBasicSerializer(read_only=True)
    file_size_human = serializers.SerializerMethodField()
    
    class Meta:
        model = FileVersion
        fields = [
            'id', 'version_number', 'file_name', 'file_size',
            'file_size_human', 'change_description', 'uploaded_by',
            'created_at'
        ]
        read_only_fields = [
            'id', 'version_number', 'file_name', 'file_size',
            'uploaded_by', 'created_at'
        ]
    
    def get_file_size_human(self, obj):
        """Get human readable file size"""
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


class FileShareSerializer(serializers.ModelSerializer):
    """Serializer for file sharing"""
    shared_by = UserBasicSerializer(read_only=True)
    shared_with = UserBasicSerializer(read_only=True)
    shared_with_email = serializers.EmailField(write_only=True)
    file_name = serializers.CharField(source='file.original_name', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = FileShare
        fields = [
            'id', 'file', 'shared_by', 'shared_with', 'shared_with_email',
            'file_name', 'can_download', 'can_view', 'can_comment',
            'expires_at', 'is_expired', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'shared_by', 'shared_with', 'file_name',
            'is_expired', 'created_at', 'updated_at'
        ]
    
    def validate_shared_with_email(self, value):
        """Validate shared with email"""
        try:
            user = User.objects.get(email=value)
            return user
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User with this email does not exist"
            )
    
    def validate(self, attrs):
        """Validate file share data"""
        request = self.context.get('request')
        file_obj = attrs.get('file')
        shared_with_user = attrs.get('shared_with_email')
        
        # Check if user owns the file
        if file_obj.user != request.user:
            raise serializers.ValidationError(
                "You can only share your own files"
            )
        
        # Check if not sharing with self
        if shared_with_user == request.user:
            raise serializers.ValidationError(
                "You cannot share a file with yourself"
            )
        
        # Check if already shared
        if FileShare.objects.filter(
            file=file_obj, shared_with=shared_with_user
        ).exists():
            raise serializers.ValidationError(
                "File is already shared with this user"
            )
        
        attrs['shared_with'] = shared_with_user
        del attrs['shared_with_email']
        
        return attrs


class FileSerializer(serializers.ModelSerializer):
    """Serializer for file listing and details"""
    user = UserBasicSerializer(read_only=True)
    file_size_human = serializers.CharField(read_only=True)
    shared_with_count = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()
    versions_count = serializers.SerializerMethodField()
    can_edit = serializers.SerializerMethodField()
    can_delete = serializers.SerializerMethodField()
    download_url = serializers.SerializerMethodField()
    
    class Meta:
        model = File
        fields = [
            'id', 'user', 'original_name', 'file_name', 'file_size',
            'file_size_human', 'file_type', 'file_extension', 'category',
            'description', 'tags', 'is_public', 'is_shared',
            'download_count', 'last_accessed', 'status', 'upload_progress',
            'shared_with_count', 'comments_count', 'versions_count',
            'can_edit', 'can_delete', 'download_url',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user', 'file_name', 'file_size', 'file_type',
            'file_extension', 'category', 'download_count', 'last_accessed',
            'status', 'upload_progress', 'created_at', 'updated_at'
        ]
    
    def get_shared_with_count(self, obj):
        """Get number of users file is shared with"""
        return obj.shares.count()
    
    def get_comments_count(self, obj):
        """Get number of comments on file"""
        return obj.comments.count()
    
    def get_versions_count(self, obj):
        """Get number of file versions"""
        return obj.versions.count()
    
    def get_can_edit(self, obj):
        """Check if current user can edit file"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.user == request.user or request.user.is_admin
    
    def get_can_delete(self, obj):
        """Check if current user can delete file"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.user == request.user or request.user.is_admin
    
    def get_download_url(self, obj):
        """Get download URL for file"""
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(f'/api/files/{obj.id}/download/')
        return None
    
    def validate_tags(self, value):
        """Validate tags"""
        if len(value) > 10:
            raise serializers.ValidationError("Maximum 10 tags allowed")
        
        cleaned_tags = []
        for tag in value:
            if isinstance(tag, str) and len(tag.strip()) >= 2:
                cleaned_tags.append(tag.strip().lower())
        
        return cleaned_tags


class FileDetailSerializer(FileSerializer):
    """Detailed file serializer with additional information"""
    comments = FileCommentSerializer(many=True, read_only=True)
    versions = FileVersionSerializer(many=True, read_only=True)
    shares = FileShareSerializer(many=True, read_only=True)
    metadata = serializers.JSONField(read_only=True)
    
    class Meta(FileSerializer.Meta):
        fields = FileSerializer.Meta.fields + [
            'comments', 'versions', 'shares', 'metadata'
        ]


class FileStatsSerializer(serializers.Serializer):
    """Serializer for file statistics"""
    total_files = serializers.IntegerField()
    total_size = serializers.IntegerField()
    total_size_human = serializers.CharField()
    files_by_category = serializers.DictField()
    files_by_month = serializers.DictField()
    most_downloaded = serializers.ListField()
    recent_uploads = serializers.ListField()
    storage_usage_percentage = serializers.FloatField()


class BulkFileActionSerializer(serializers.Serializer):
    """Serializer for bulk file actions"""
    file_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=50
    )
    action = serializers.ChoiceField(
        choices=['delete', 'archive', 'make_public', 'make_private']
    )
    
    def validate_file_ids(self, value):
        """Validate file IDs exist and user has permission"""
        request = self.context.get('request')
        user = request.user
        
        # Check if files exist and user has permission
        files = File.objects.filter(id__in=value, deleted_at__isnull=True)
        
        if not user.is_admin:
            files = files.filter(user=user)
        
        if files.count() != len(value):
            raise serializers.ValidationError(
                "Some files do not exist or you don't have permission to access them"
            )
        
        return value