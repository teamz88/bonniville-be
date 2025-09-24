from django.shortcuts import get_object_or_404
from django.db.models import Q, Count
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.authentication.permissions import IsOwnerOrAdmin
from .models import Folder, File
from .folder_serializers import (
    FolderSerializer, FolderDetailSerializer, FolderCreateSerializer,
    FolderTreeSerializer, MoveFolderSerializer
)


class FolderListCreateView(generics.ListCreateAPIView):
    """List folders and create new folders"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return FolderCreateSerializer
        return FolderSerializer
    
    def get_queryset(self):
        user = self.request.user
        queryset = Folder.objects.filter(
            user=user,
            deleted_at__isnull=True
        ).select_related('parent').prefetch_related('subfolders', 'files')
        
        # Filter by parent folder if specified
        parent_id = self.request.query_params.get('parent')
        if parent_id:
            if parent_id.lower() == 'root':
                queryset = queryset.filter(parent__isnull=True)
            else:
                queryset = queryset.filter(parent_id=parent_id)
        
        return queryset.order_by('name')
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class FolderDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a folder"""
    serializer_class = FolderDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'id'
    
    def get_queryset(self):
        return Folder.objects.filter(
            user=self.request.user,
            deleted_at__isnull=True
        ).select_related('parent').prefetch_related('subfolders', 'files')
    
    def perform_destroy(self, instance):
        """Soft delete the folder and all its contents"""
        instance.soft_delete()


class FolderTreeView(APIView):
    """Get folder tree structure"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get all folders for the user
        folders = Folder.objects.filter(
            user=user,
            deleted_at__isnull=True
        ).select_related('parent').prefetch_related('subfolders', 'files')
        
        # Build tree structure starting from root folders
        root_folders = folders.filter(parent__isnull=True)
        serializer = FolderTreeSerializer(root_folders, many=True, context={'request': request})
        
        return Response({
            'folders': serializer.data,
            'total_folders': folders.count()
        })


class MoveFolderView(APIView):
    """Move folder to a different parent"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, folder_id):
        folder = get_object_or_404(
            Folder,
            id=folder_id,
            user=request.user,
            deleted_at__isnull=True
        )
        
        serializer = MoveFolderSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            new_parent_id = serializer.validated_data.get('parent_id')
            
            # Validate the move
            if new_parent_id:
                new_parent = get_object_or_404(
                    Folder,
                    id=new_parent_id,
                    user=request.user,
                    deleted_at__isnull=True
                )
                
                # Check for circular reference
                if folder in new_parent.get_ancestors() or folder == new_parent:
                    return Response(
                        {'error': 'Cannot move folder to itself or its descendant'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                folder.parent = new_parent
            else:
                folder.parent = None
            
            folder.save()
            
            folder_serializer = FolderDetailSerializer(folder, context={'request': request})
            return Response({
                'message': 'Folder moved successfully',
                'folder': folder_serializer.data
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def restore_folder(request, folder_id):
    """Restore a soft-deleted folder"""
    folder = get_object_or_404(
        Folder,
        id=folder_id,
        user=request.user,
        deleted_at__isnull=False
    )
    
    folder.restore()
    
    serializer = FolderDetailSerializer(folder, context={'request': request})
    return Response({
        'message': 'Folder restored successfully',
        'folder': serializer.data
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def folder_contents(request, folder_id):
    """Get contents of a folder (subfolders and files)"""
    folder = get_object_or_404(
        Folder,
        id=folder_id,
        user=request.user,
        deleted_at__isnull=True
    )
    
    # Get subfolders
    subfolders = folder.subfolders.filter(deleted_at__isnull=True)
    folder_serializer = FolderSerializer(subfolders, many=True, context={'request': request})
    
    # Get files in this folder
    files = folder.files.filter(deleted_at__isnull=True)
    from .serializers import FileSerializer
    file_serializer = FileSerializer(files, many=True, context={'request': request})
    
    return Response({
        'folder': FolderDetailSerializer(folder, context={'request': request}).data,
        'subfolders': folder_serializer.data,
        'files': file_serializer.data,
        'total_items': subfolders.count() + files.count()
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def folder_breadcrumbs(request, folder_id):
    """Get breadcrumb path for a folder"""
    folder = get_object_or_404(
        Folder,
        id=folder_id,
        user=request.user,
        deleted_at__isnull=True
    )
    
    # Get all ancestors including the folder itself
    ancestors = list(folder.get_ancestors()) + [folder]
    
    breadcrumbs = []
    for ancestor in ancestors:
        breadcrumbs.append({
            'id': ancestor.id,
            'name': ancestor.name,
            'path': ancestor.get_full_path()
        })
    
    return Response({
        'breadcrumbs': breadcrumbs,
        'current_folder': {
            'id': folder.id,
            'name': folder.name,
            'path': folder.get_full_path()
        }
    })