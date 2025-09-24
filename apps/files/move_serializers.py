from rest_framework import serializers
from django.shortcuts import get_object_or_404
from .models import File, Folder


class MoveFileToFolderSerializer(serializers.Serializer):
    """Serializer for moving a file to a folder"""
    folder_id = serializers.UUIDField(required=False, allow_null=True)
    
    def validate_folder_id(self, value):
        """Validate folder exists and belongs to user"""
        if value:
            request = self.context.get('request')
            if not request or not request.user:
                raise serializers.ValidationError("Authentication required")
            
            try:
                folder = Folder.objects.get(
                    id=value,
                    user=request.user,
                    deleted_at__isnull=True
                )
                return value
            except Folder.DoesNotExist:
                raise serializers.ValidationError("Folder not found or access denied")
        
        return value
    
    def save(self, file_instance):
        """Move the file to the specified folder"""
        folder_id = self.validated_data.get('folder_id')
        
        if folder_id:
            folder = get_object_or_404(
                Folder,
                id=folder_id,
                user=self.context['request'].user,
                deleted_at__isnull=True
            )
            file_instance.folder = folder
        else:
            # Move to root (no folder)
            file_instance.folder = None
        
        file_instance.save(update_fields=['folder'])
        return file_instance