from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db.models import Sum
from .models import Folder, File

User = get_user_model()


class UserBasicSerializer(serializers.ModelSerializer):
    """Basic user serializer for folder sharing"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


class FolderSerializer(serializers.ModelSerializer):
    """Serializer for folder listing and details"""
    user = UserBasicSerializer(read_only=True)
    parent_name = serializers.CharField(source='parent.name', read_only=True)
    subfolders_count = serializers.SerializerMethodField()
    files_count = serializers.SerializerMethodField()
    full_path = serializers.CharField(read_only=True)
    
    class Meta:
        model = Folder
        fields = [
            'id', 'name', 'description', 'color', 'user', 'parent', 'parent_name',
            'subfolders_count', 'files_count', 'full_path', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']
    
    def get_subfolders_count(self, obj):
        return obj.subfolders.filter(deleted_at__isnull=True).count()
    
    def get_files_count(self, obj):
        return obj.files.filter(deleted_at__isnull=True).count()


class FolderCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating folders"""
    
    class Meta:
        model = Folder
        fields = ['name', 'description', 'color', 'parent']
    
    def validate_name(self, value):
        """Validate folder name"""
        if not value or not value.strip():
            raise serializers.ValidationError("Folder name cannot be empty")
        
        # Check for invalid characters
        invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in invalid_chars:
            if char in value:
                raise serializers.ValidationError(
                    f"Folder name cannot contain '{char}'"
                )
        
        # Check length
        if len(value.strip()) > 255:
            raise serializers.ValidationError(
                "Folder name cannot exceed 255 characters"
            )
        
        return value.strip()
    
    def validate_parent(self, value):
        """Validate parent folder"""
        if value:
            request = self.context.get('request')
            if request and request.user:
                # Check if parent belongs to user
                if value.user != request.user:
                    raise serializers.ValidationError(
                        "Parent folder not found or access denied"
                    )
                
                # Check if parent is not deleted
                if value.deleted_at:
                    raise serializers.ValidationError(
                        "Cannot create folder in deleted parent"
                    )
        
        return value
    
    def validate(self, attrs):
        """Validate folder creation data"""
        request = self.context.get('request')
        if request and request.user:
            name = attrs.get('name')
            parent = attrs.get('parent')
            
            # Check for duplicate names in same parent
            existing = Folder.objects.filter(
                user=request.user,
                parent=parent,
                name__iexact=name,
                deleted_at__isnull=True
            )
            
            if existing.exists():
                raise serializers.ValidationError({
                    'name': 'A folder with this name already exists in the selected location'
                })
        
        return attrs


class FolderDetailSerializer(FolderSerializer):
    """Detailed folder serializer with subfolders and files"""
    subfolders = serializers.SerializerMethodField()
    recent_files = serializers.SerializerMethodField()
    total_size = serializers.SerializerMethodField()
    
    class Meta(FolderSerializer.Meta):
        fields = FolderSerializer.Meta.fields + [
            'subfolders', 'recent_files', 'total_size'
        ]
    
    def get_subfolders(self, obj):
        subfolders = obj.subfolders.filter(deleted_at__isnull=True)[:10]
        return FolderSerializer(subfolders, many=True).data
    
    def get_recent_files(self, obj):
        from .serializers import FileSerializer
        files = obj.files.filter(deleted_at__isnull=True).order_by('-created_at')[:5]
        return FileSerializer(files, many=True).data
    
    def get_total_size(self, obj):
        total_size = obj.get_all_files().aggregate(
            total=Sum('file_size')
        )['total'] or 0
        
        # Convert to human readable format
        def format_size(size_bytes):
            if size_bytes == 0:
                return "0 B"
            size_names = ["B", "KB", "MB", "GB", "TB"]
            import math
            i = int(math.floor(math.log(size_bytes, 1024)))
            p = math.pow(1024, i)
            s = round(size_bytes / p, 2)
            return f"{s} {size_names[i]}"
        
        return {
            'bytes': total_size,
            'human': format_size(total_size)
        }


class FolderTreeSerializer(serializers.ModelSerializer):
    """Serializer for folder tree structure"""
    subfolders = serializers.SerializerMethodField()
    files_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Folder
        fields = [
            'id', 'name', 'description', 'color', 'subfolders', 'files_count',
            'created_at', 'updated_at'
        ]
    
    def get_subfolders(self, obj):
        subfolders = obj.subfolders.filter(deleted_at__isnull=True)
        return FolderTreeSerializer(subfolders, many=True).data
    
    def get_files_count(self, obj):
        return obj.files.filter(deleted_at__isnull=True).count()


class MoveFolderSerializer(serializers.Serializer):
    """Serializer for moving folders"""
    parent_id = serializers.UUIDField(required=False, allow_null=True)
    
    def validate_parent_id(self, value):
        """Validate parent folder for move operation"""
        if value:
            request = self.context.get('request')
            folder = self.context.get('folder')
            
            if request and request.user:
                try:
                    parent = Folder.objects.get(id=value, user=request.user, deleted_at__isnull=True)
                    
                    # Check if trying to move folder into itself or its subfolder
                    if folder and (parent.id == folder.id or parent.full_path.startswith(folder.full_path + '/')):
                        raise serializers.ValidationError(
                            "Cannot move folder into itself or its subfolder"
                        )
                    
                    return parent
                except Folder.DoesNotExist:
                    raise serializers.ValidationError("Parent folder not found")
        
        return None


class FolderStatsSerializer(serializers.Serializer):
    """Serializer for folder statistics"""
    total_folders = serializers.IntegerField()
    total_files = serializers.IntegerField()
    total_size = serializers.IntegerField()
    total_size_human = serializers.CharField()
    folder_depth = serializers.IntegerField()
    largest_folder = serializers.DictField()
    most_files_folder = serializers.DictField()