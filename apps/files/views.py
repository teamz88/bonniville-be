from datetime import timedelta
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q, Count, Sum
from django.contrib.auth import get_user_model
from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from apps.authentication.permissions import IsOwnerOrAdmin, IsActiveSubscription
from .models import File, FileShare, FileComment, FileVersion
from .serializers import (
    FileUploadSerializer, FileSerializer, FileDetailSerializer,
    FileShareSerializer, FileCommentSerializer, FileVersionSerializer,
    FileStatsSerializer, BulkFileActionSerializer
)
from .move_serializers import MoveFileToFolderSerializer
from .services import FileService
from .filters import FileFilter

User = get_user_model()


class FileUploadView(APIView):
    """Upload files to local storage"""
    permission_classes = [permissions.IsAuthenticated, IsActiveSubscription]
    parser_classes = [MultiPartParser, FormParser]
    
    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():
            file_service = FileService()
            
            success, file_obj, message = file_service.upload_file(
                user=request.user,
                uploaded_file=serializer.validated_data['file'],
                description=serializer.validated_data.get('description', ''),
                tags=serializer.validated_data.get('tags', []),
                is_public=serializer.validated_data.get('is_public', False)
            )
            
            if success:
                # Send file to RAG API after successful upload
                rag_success, rag_response, rag_message = file_service.send_file_to_rag_api(
                    file_obj, request.user
                )
                
                file_serializer = FileSerializer(file_obj, context={'request': request})
                response_data = {
                    'message': message,
                    'file': file_serializer.data,
                    'rag_integration': {
                        'success': rag_success,
                        'message': rag_message
                    }
                }
                
                # Include RAG response data if successful
                if rag_success and rag_response:
                    response_data['rag_integration']['response'] = rag_response
                
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'error': message
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PublicFileUploadView(APIView):
    """Public file upload endpoint - no authentication required"""
    permission_classes = []  # No authentication required
    parser_classes = [MultiPartParser, FormParser]
    
    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():
            file_service = FileService()
            
            # For public uploads, we need to handle the case where there's no user
            # We'll create a special system user or handle anonymous uploads
            success, file_obj, message = file_service.upload_public_file(
                uploaded_file=serializer.validated_data['file'],
                description=serializer.validated_data.get('description', ''),
                tags=serializer.validated_data.get('tags', [])
            )
            
            if success:
                file_serializer = FileSerializer(file_obj, context={'request': request})
                response_data = {
                    'message': message,
                    'file': file_serializer.data
                }
                
                # Try to upload file to RAG API (non-blocking)
                try:
                    from apps.chat.services import AIService
                    ai_service = AIService()
                    # Use system_anonymous email for public uploads
                    rag_result = ai_service.upload_file_to_rag(file_obj, 'system_anonymous@bonniville.com')
                    
                    if rag_result['success']:
                        response_data['rag_upload'] = 'success'
                        response_data['rag_message'] = 'File uploaded to RAG successfully'
                    else:
                        response_data['rag_upload'] = 'failed'
                        response_data['rag_message'] = rag_result.get('error', 'RAG upload failed')
                        
                except Exception as e:
                    # Log the error but don't fail the file upload
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"RAG upload failed for file {file_obj.original_name}: {str(e)}")
                    response_data['rag_upload'] = 'failed'
                    response_data['rag_message'] = 'RAG service temporarily unavailable'
                
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'error': message
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FileListView(generics.ListAPIView):
    """List files with filtering and search"""
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = FileFilter
    search_fields = ['original_name', 'description', 'tags']
    ordering_fields = ['created_at', 'updated_at', 'file_size', 'download_count']
    ordering = ['-created_at']
    
    def get_queryset(self):
        user = self.request.user
        
        if user.is_admin:
            # Admin can see all files
            queryset = File.objects.filter(deleted_at__isnull=True)
        else:
            # Users see their own files and files shared with them
            queryset = File.objects.filter(
                Q(user=user) | 
                Q(is_public=True) |
                Q(shares__shared_with=user, shares__can_view=True),
                deleted_at__isnull=True
            ).distinct()
        
        return queryset.select_related('user').prefetch_related('shares', 'comments')


class FileDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a file"""
    serializer_class = FileDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'id'
    
    def get_queryset(self):
        user = self.request.user
        
        if user.is_admin:
            return File.objects.filter(deleted_at__isnull=True)
        else:
            return File.objects.filter(
                Q(user=user) | 
                Q(is_public=True) |
                Q(shares__shared_with=user, shares__can_view=True),
                deleted_at__isnull=True
            ).distinct()
    
    def perform_destroy(self, instance):
        """Soft delete the file"""
        file_service = FileService()
        success, message = file_service.delete_file(
            instance, self.request.user, hard_delete=False
        )
        if not success:
            return Response(
                {'error': message}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class FileDownloadView(APIView):
    """Download file from local storage"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, file_id):
        try:
            file_obj = get_object_or_404(File, id=file_id, deleted_at__isnull=True)
            file_service = FileService()
            
            success, response, message = file_service.download_file(file_obj, request.user)
            
            if success:
                # Create streaming response
                def file_iterator():
                    try:
                        while True:
                            chunk = response.read(8192)
                            if not chunk:
                                break
                            yield chunk
                    finally:
                        response.close()
                
                streaming_response = StreamingHttpResponse(
                    file_iterator(),
                    content_type=file_obj.file_type
                )
                streaming_response['Content-Disposition'] = (
                    f'attachment; filename="{file_obj.original_name}"'
                )
                streaming_response['Content-Length'] = file_obj.file_size
                
                return streaming_response
            else:
                return Response(
                    {'error': message}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FileShareView(generics.CreateAPIView):
    """Share file with other users"""
    serializer_class = FileShareSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        serializer.save(shared_by=self.request.user)


class FileShareListView(generics.ListAPIView):
    """List file shares"""
    serializer_class = FileShareSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        file_id = self.kwargs.get('file_id')
        
        if file_id:
            # Get shares for specific file
            file_obj = get_object_or_404(File, id=file_id)
            if file_obj.user != user and not user.is_admin:
                return FileShare.objects.none()
            return file_obj.shares.all()
        else:
            # Get all shares for user
            return FileShare.objects.filter(
                Q(shared_by=user) | Q(shared_with=user)
            )


class FileCommentView(generics.CreateAPIView):
    """Add comment to file"""
    serializer_class = FileCommentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def perform_create(self, serializer):
        file_id = self.kwargs.get('file_id')
        file_obj = get_object_or_404(File, id=file_id)
        
        # Check if user can comment on file
        file_service = FileService()
        if not file_service._can_access_file(file_obj, self.request.user):
            return Response(
                {'error': 'Permission denied'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer.save(user=self.request.user, file=file_obj)


class FileCommentListView(generics.ListAPIView):
    """List file comments"""
    serializer_class = FileCommentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        file_id = self.kwargs.get('file_id')
        file_obj = get_object_or_404(File, id=file_id)
        
        # Check if user can view file
        file_service = FileService()
        if not file_service._can_access_file(file_obj, self.request.user):
            return FileComment.objects.none()
        
        return file_obj.comments.filter(parent__isnull=True).order_by('created_at')


class FileVersionListView(generics.ListAPIView):
    """List file versions"""
    serializer_class = FileVersionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        file_id = self.kwargs.get('file_id')
        file_obj = get_object_or_404(File, id=file_id)
        
        # Check if user can view file
        file_service = FileService()
        if not file_service._can_access_file(file_obj, self.request.user):
            return FileVersion.objects.none()
        
        return file_obj.versions.all()


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def file_stats(request):
    """Get file statistics for current user"""
    file_service = FileService()
    stats = file_service.get_user_storage_stats(request.user)
    
    serializer = FileStatsSerializer(stats)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def bulk_file_action(request):
    """Perform bulk actions on files"""
    serializer = BulkFileActionSerializer(
        data=request.data, 
        context={'request': request}
    )
    
    if serializer.is_valid():
        file_ids = serializer.validated_data['file_ids']
        action = serializer.validated_data['action']
        
        # Get files
        files = File.objects.filter(
            id__in=file_ids, 
            deleted_at__isnull=True
        )
        
        if not request.user.is_admin:
            files = files.filter(user=request.user)
        
        success_count = 0
        error_count = 0
        
        for file_obj in files:
            try:
                if action == 'delete':
                    file_obj.soft_delete()
                elif action == 'archive':
                    file_obj.is_archived = True
                    file_obj.save()
                elif action == 'make_public':
                    file_obj.is_public = True
                    file_obj.save()
                elif action == 'make_private':
                    file_obj.is_public = False
                    file_obj.save()
                
                success_count += 1
            except Exception:
                error_count += 1
        
        return Response({
            'message': f'Action completed. {success_count} files processed successfully.',
            'success_count': success_count,
            'error_count': error_count
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_download_url(request, file_id):
    """Get presigned download URL for file"""
    try:
        file_obj = get_object_or_404(File, id=file_id, deleted_at__isnull=True)
        file_service = FileService()
        
        # Get expiration time from query params (default 1 hour)
        expires_hours = int(request.GET.get('expires', 1))
        expires = timedelta(hours=expires_hours)
        
        success, url, message = file_service.get_download_url(
            file_obj, request.user, expires
        )
        
        if success:
            return Response({
                'download_url': url,
                'expires_in': expires_hours * 3600,  # seconds
                'file_name': file_obj.original_name
            })
        else:
            return Response(
                {'error': message}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['PATCH'])
@permission_classes([permissions.IsAuthenticated])
def move_file_to_folder(request, file_id):
    """Move a file to a specific folder"""
    try:
        file_obj = get_object_or_404(
            File,
            id=file_id,
            user=request.user,
            deleted_at__isnull=True
        )
        
        serializer = MoveFileToFolderSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            updated_file = serializer.save(file_obj)
            
            # Return updated file data
            file_serializer = FileSerializer(updated_file, context={'request': request})
            return Response({
                'message': 'File moved successfully',
                'file': file_serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        return Response({
            'error': 'Failed to move file',
            'detail': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def admin_delete_file(request, file_id):
    """Admin-only hard delete file endpoint"""
    if not request.user.is_admin:
        return Response(
            {'error': 'Admin access required'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        file_obj = get_object_or_404(File, id=file_id)
        file_service = FileService()
        
        # Hard delete for admin
        success, message = file_service.delete_file(
            file_obj, request.user, hard_delete=True
        )
        
        if success:
            return Response({'message': message})
        else:
            return Response(
                {'error': message}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        return Response(
            {'error': f'Failed to delete file: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def admin_bulk_delete(request):
    """Admin-only bulk hard delete files"""
    if not request.user.is_admin:
        return Response(
            {'error': 'Admin access required'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    file_ids = request.data.get('file_ids', [])
    if not file_ids:
        return Response(
            {'error': 'No file IDs provided'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    files = File.objects.filter(id__in=file_ids)
    file_service = FileService()
    
    success_count = 0
    error_count = 0
    
    for file_obj in files:
        try:
            success, message = file_service.delete_file(
                file_obj, request.user, hard_delete=True
            )
            if success:
                success_count += 1
            else:
                error_count += 1
        except Exception:
            error_count += 1
    
    return Response({
        'message': f'Admin delete completed. {success_count} files permanently deleted.',
        'success_count': success_count,
        'error_count': error_count
    })


class AdminFileAnalyticsView(APIView):
    """Admin-only file analytics"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        if not request.user.is_admin:
            return Response(
                {'error': 'Admin access required'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Total files and storage
        total_files = File.objects.filter(deleted_at__isnull=True).count()
        total_storage = File.objects.filter(
            deleted_at__isnull=True
        ).aggregate(total=Sum('file_size'))['total'] or 0
        
        # Files by category
        files_by_category = File.objects.filter(
            deleted_at__isnull=True
        ).values('category').annotate(count=Count('id'))
        
        # Files by user
        files_by_user = File.objects.filter(
            deleted_at__isnull=True
        ).values(
            'user__username', 'user__email'
        ).annotate(
            file_count=Count('id'),
            total_size=Sum('file_size')
        ).order_by('-file_count')[:10]
        
        # Recent uploads (last 7 days)
        recent_date = timezone.now() - timedelta(days=7)
        recent_uploads = File.objects.filter(
            created_at__gte=recent_date,
            deleted_at__isnull=True
        ).count()
        
        # Most downloaded files
        most_downloaded = File.objects.filter(
            download_count__gt=0,
            deleted_at__isnull=True
        ).order_by('-download_count')[:10]
        
        # Storage by month (last 12 months)
        monthly_stats = []
        for i in range(12):
            month_start = timezone.now().replace(day=1) - timedelta(days=30*i)
            month_end = month_start + timedelta(days=31)
            
            month_files = File.objects.filter(
                created_at__gte=month_start,
                created_at__lt=month_end,
                deleted_at__isnull=True
            ).aggregate(
                count=Count('id'),
                size=Sum('file_size')
            )
            
            monthly_stats.append({
                'month': month_start.strftime('%Y-%m'),
                'files': month_files['count'] or 0,
                'size': month_files['size'] or 0
            })
        
        return Response({
            'total_files': total_files,
            'total_storage': total_storage,
            'total_storage_human': self._format_file_size(total_storage),
            'files_by_category': list(files_by_category),
            'files_by_user': list(files_by_user),
            'recent_uploads': recent_uploads,
            'most_downloaded': [
                {
                    'id': f.id,
                    'name': f.original_name,
                    'user': f.user.username,
                    'downloads': f.download_count,
                    'size': f.file_size
                }
                for f in most_downloaded
            ],
            'monthly_stats': monthly_stats
        })
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if not size_bytes:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"