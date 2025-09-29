from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.http import StreamingHttpResponse, HttpResponse
import json
import requests
import logging

from .models import Conversation, ChatMessage, ChatTemplate, Folder
from .serializers import (
    ConversationSerializer,
    ConversationDetailSerializer,
    ChatMessageSerializer,
    ChatRequestSerializer,
    MessageFeedbackSerializer,
    ChatTemplateSerializer,
    ConversationStatsSerializer,
    FolderSerializer,
    RAGMessageSerializer
)
from .services import ChatService, FeedbackService
from apps.authentication.permissions import IsOwnerOrAdmin, IsAdminUser
from apps.core.notifications import notification_service


class ChatView(APIView):
    """Main chat endpoint for sending messages and getting AI responses."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Send a chat message and get AI response."""
        serializer = ChatRequestSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        chat_service = ChatService()
        result = chat_service.process_chat_message(
            user=request.user,
            message_content=serializer.validated_data['message'],
            conversation_id=serializer.validated_data.get('conversation_id'),
            template_id=serializer.validated_data.get('template_id'),
            folder_id=serializer.validated_data.get('folder_id')
        )
        
        if result['success']:
            response_data = {
                'conversation_id': result['conversation_id'],
                'user_message': ChatMessageSerializer(result['user_message']).data,
                'assistant_message': ChatMessageSerializer(result['assistant_message']).data,
                'tokens_used': result['tokens_used'],
                'response_time_ms': result['response_time_ms']
            }
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Failed to process chat message',
                'detail': result.get('error', 'Unknown error')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChatStreamView(APIView):
    """Streaming chat endpoint for real-time AI responses."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def options(self, request):
        """Handle preflight CORS requests."""
        response = Response()
        response['Access-Control-Allow-Origin'] = 'http://localhost:3000, https://junkgpt.com'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Cache-Control, Authorization, Content-Type'
        response['Access-Control-Allow-Credentials'] = 'true'
        return response
    
    def get_permissions(self):
        """Allow OPTIONS requests without authentication."""
        if self.request.method == 'OPTIONS':
            return []
        return super().get_permissions()
    
    def post(self, request):
        """Send a chat message and get streaming AI response."""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"ChatStreamView POST called by user: {request.user}")
        logger.info(f"Request data: {request.data}")
        
        serializer = ChatRequestSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        logger.info(f"Serializer validated data: {serializer.validated_data}")
        
        def generate_stream():
            """Generator function for streaming response."""
            logger.info("Starting generate_stream function")
            chat_service = ChatService()
            
            try:
                logger.info("About to call process_chat_message_stream")
                chunk_count = 0
                for chunk in chat_service.process_chat_message_stream(
                    user=request.user,
                    message_content=serializer.validated_data['message'],
                    conversation_id=serializer.validated_data.get('conversation_id'),
                    template_id=serializer.validated_data.get('template_id'),
                    folder_id=serializer.validated_data.get('folder_id')
                ):
                    chunk_count += 1
                    # Format chunk as Server-Sent Event
                    event_data = json.dumps(chunk)
                    yield f"data: {event_data}\n\n"
                
                logger.info(f"Stream completed with {chunk_count} chunks")
                    
            except Exception as e:
                # Send error event
                error_chunk = {
                    'type': 'error',
                    'response': 'An error occurred while processing your message.',
                    'sources': [],
                    'error': str(e),
                    'success': False
                }
                event_data = json.dumps(error_chunk)
                yield f"data: {event_data}\n\n"
        
        response = StreamingHttpResponse(
            generate_stream(),
            content_type='text/event-stream'
        )
        response['Cache-Control'] = 'no-cache'
        response['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response['Access-Control-Allow-Headers'] = 'Cache-Control, Authorization, Content-Type'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response['Access-Control-Allow-Credentials'] = 'true'
        
        return response


class ConversationListView(generics.ListCreateAPIView):
    """List and create user's conversations."""
    
    serializer_class = ConversationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = self.request.user.conversations.all()
        
        # Filter by archived status
        is_archived = self.request.query_params.get('archived')
        if is_archived is not None:
            queryset = queryset.filter(is_archived=is_archived.lower() == 'true')
        
        # Filter by pinned status
        is_pinned = self.request.query_params.get('pinned')
        if is_pinned is not None:
            queryset = queryset.filter(is_pinned=is_pinned.lower() == 'true')
        
        # Search by title
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(title__icontains=search)
        
        # Order by
        ordering = self.request.query_params.get('ordering', '-updated_at')
        if ordering:
            queryset = queryset.order_by(ordering)
        
        return queryset
    
    def perform_create(self, serializer):
        """Associate the conversation with the authenticated user."""
        serializer.save(user=self.request.user)


class ConversationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a specific conversation."""
    
    serializer_class = ConversationDetailSerializer
    permission_classes = [IsOwnerOrAdmin]
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return Conversation.objects.none()
        if self.request.user.is_admin:
            return Conversation.objects.all()
        return self.request.user.conversations.all()
    
    def get_serializer_class(self):
        if self.request.method == 'GET':
            return ConversationDetailSerializer
        return ConversationSerializer


class ConversationHistoryView(generics.ListAPIView):
    """Get chat history for a specific conversation."""
    
    serializer_class = ChatMessageSerializer
    permission_classes = [IsOwnerOrAdmin]
    
    def get_queryset(self):
        conversation_id = self.kwargs['conversation_id']
        
        # Verify user has access to this conversation
        if self.request.user.is_admin:
            conversation = get_object_or_404(Conversation, id=conversation_id)
        else:
            conversation = get_object_or_404(
                Conversation,
                id=conversation_id,
                user=self.request.user
            )
        
        return conversation.messages.all().order_by('created_at')


class MessageFeedbackView(APIView):
    """Submit feedback for a chat message."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, message_id):
        """Submit feedback for a message."""
        # Get message and verify ownership
        if request.user.is_admin:
            message = get_object_or_404(ChatMessage, id=message_id)
        else:
            message = get_object_or_404(
                ChatMessage,
                id=message_id,
                user=request.user
            )
        
        serializer = MessageFeedbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        message.mark_as_helpful(
            helpful=serializer.validated_data['is_helpful'],
            comment=serializer.validated_data.get('comment', '')
        )
        
        return Response({
            'message': 'Feedback submitted successfully',
            'message_data': ChatMessageSerializer(message).data
        }, status=status.HTTP_200_OK)


class FolderListView(generics.ListCreateAPIView):
    """List and create folders for the authenticated user."""
    
    serializer_class = FolderSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Return folders for the authenticated user."""
        return Folder.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        """Create a new folder for the authenticated user."""
        serializer.save(user=self.request.user)


class FolderDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a specific folder."""
    
    serializer_class = FolderSerializer
    permission_classes = [IsOwnerOrAdmin]
    
    def get_queryset(self):
        """Return folders for the authenticated user."""
        return Folder.objects.filter(user=self.request.user)
    
    def perform_destroy(self, instance):
        """Delete all conversations in the folder before deleting the folder."""
        # Delete all conversations in this folder
        conversations_in_folder = instance.conversations.all()
        conversations_in_folder.delete()
        
        # Now delete the folder
        super().perform_destroy(instance)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def move_conversation_to_folder(request, conversation_id):
    """Move a conversation to a specific folder."""
    try:
        conversation = get_object_or_404(
            Conversation,
            id=conversation_id,
            user=request.user
        )
        
        folder_id = request.data.get('folder_id')
        
        if folder_id:
            folder = get_object_or_404(
                Folder,
                id=folder_id,
                user=request.user
            )
            conversation.folder = folder
        else:
            # Remove from folder (move to root)
            conversation.folder = None
        
        conversation.save()
        
        serializer = ConversationSerializer(conversation)
        return Response({
            'message': 'Conversation moved successfully',
            'conversation': serializer.data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': 'Failed to move conversation',
            'detail': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def folder_conversations(request, folder_id):
    """Get all conversations in a specific folder."""
    try:
        folder = get_object_or_404(
            Folder,
            id=folder_id,
            user=request.user
        )
        
        conversations = Conversation.objects.filter(
            folder=folder,
            user=request.user
        ).order_by('-updated_at')
        
        serializer = ConversationSerializer(conversations, many=True)
        return Response({
            'folder': FolderSerializer(folder).data,
            'conversations': serializer.data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': 'Failed to get folder conversations',
            'detail': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


class FeedbackView(APIView):
    """New feedback API for thumb up/down functionality with RAG integration."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Submit feedback with question, answer, and comment to RAG API."""
        question = request.data.get('question', '')
        answer = request.data.get('answer', '')
        comment = request.data.get('comment', '')
        
        if not question or not answer:
            return Response({
                'error': 'Question and answer are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Determine feedback type based on comment
        feedback_type = 'thumbs_up' if comment == 'thumb up' else 'thumbs_down'
        
        # Send notification about question submission
        try:
            notification_service.send_question_notification(
                user_email=request.user.email,
                question=question,
                user_id=request.user.id
            )
        except Exception as notification_error:
            # Log error but don't fail the request
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send question notification: {notification_error}")
        
        # Use FeedbackService to submit to RAG API
        feedback_service = FeedbackService()
        result = feedback_service.submit_thumbs_feedback(
            question=question,
            answer=answer,
            feedback_type=feedback_type,
            comment=comment,
            user=request.user
        )
        
        if result['success']:
            return Response({
                'message': 'Feedback submitted successfully to RAG API',
                'feedback_type': result['feedback_type'],
                'response_time_ms': result['response_time_ms'],
                'rag_response': result['response']
            }, status=status.HTTP_201_CREATED)
        else:
            # Send error notification
            try:
                notification_service.send_error_notification(
                    user_email=request.user.email,
                    error_message=result['error'],
                    user_id=request.user.id,
                    context="feedback_submission"
                )
            except Exception as notification_error:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send error notification: {notification_error}")
            
            return Response({
                'error': 'Failed to submit feedback to RAG API',
                'details': result['error'],
                'response_time_ms': result['response_time_ms']
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FeedbackListView(APIView):
    """List feedbacks with status filtering from RAG API."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get feedbacks with optional status filtering from RAG API."""
        status_filter = request.query_params.get('status')
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')
        
        # Convert status filter to boolean if provided
        status_bool = None
        if status_filter is not None:
            status_bool = status_filter.lower() == 'true'
        
        # Use FeedbackService to get feedbacks from RAG API
        feedback_service = FeedbackService()
        result = feedback_service.get_feedbacks_by_status(
            status=status_bool,
            date_from=date_from,
            date_to=date_to
        )
        
        if result['success']:
            feedbacks = result['data'].get('feedbacks', [])
            
            return Response({
                'feedbacks': feedbacks,
                'count': len(feedbacks),
                'status_filter': status_filter,
                'source': 'RAG API'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Failed to get feedbacks from RAG API',
                'details': result['error'],
                'feedbacks': [],
                'count': 0
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RAGFeedbackAnalyticsView(APIView):
    """Get detailed feedback analytics from RAG API."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get comprehensive feedback analytics from RAG API."""
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')
        
        feedback_service = FeedbackService()
        result = feedback_service.get_feedback_analytics(
            date_from=date_from,
            date_to=date_to
        )
        
        if result['success']:
            analytics_data = result['data']
            
            # Add summary statistics
            feedbacks = analytics_data.get('feedbacks', [])
            thumbs_up_count = len([f for f in feedbacks if f.get('feedback_type') == 'thumbs_up'])
            thumbs_down_count = len([f for f in feedbacks if f.get('feedback_type') == 'thumbs_down'])
            total_feedback = len(feedbacks)
            
            satisfaction_rate = (thumbs_up_count / total_feedback * 100) if total_feedback > 0 else 0
            
            return Response({
                'analytics': analytics_data,
                'summary': {
                    'total_feedback': total_feedback,
                    'thumbs_up_count': thumbs_up_count,
                    'thumbs_down_count': thumbs_down_count,
                    'satisfaction_rate': round(satisfaction_rate, 2)
                },
                'source': 'RAG API',
                'date_range': {
                    'from': date_from,
                    'to': date_to
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Failed to get analytics from RAG API',
                'details': result['error']
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChatTemplateListView(generics.ListCreateAPIView):
    """List and create chat templates."""
    
    serializer_class = ChatTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Users can see public templates and their own templates
        if self.request.user.is_admin:
            queryset = ChatTemplate.objects.all()
        else:
            queryset = ChatTemplate.objects.filter(
                Q(is_public=True) | Q(created_by=self.request.user)
            )
        
        # Filter by category
        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(category=category)
        
        # Search by name or description
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(description__icontains=search)
            )
        
        return queryset.order_by('-usage_count', 'name')


class ChatTemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a specific chat template."""
    
    serializer_class = ChatTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return ChatTemplate.objects.none()
        if self.request.user.is_admin:
            return ChatTemplate.objects.all()
        return ChatTemplate.objects.filter(
            Q(is_public=True) | Q(created_by=self.request.user)
        )
    
    def get_object(self):
        obj = super().get_object()
        
        # Only allow updates/deletes for owned templates or admin
        if self.request.method in ['PUT', 'PATCH', 'DELETE']:
            if not (self.request.user.is_admin or obj.created_by == self.request.user):
                self.permission_denied(
                    self.request,
                    message="You can only modify your own templates."
                )
        
        return obj


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def conversation_stats(request):
    """Get conversation statistics for the current user."""
    chat_service = ChatService()
    stats = chat_service.get_conversation_stats(request.user)
    
    serializer = ConversationStatsSerializer(stats)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def archive_conversation(request, conversation_id):
    """Archive a conversation."""
    chat_service = ChatService()
    success = chat_service.archive_conversation(request.user, conversation_id)
    
    if success:
        return Response({
            'message': 'Conversation archived successfully'
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'error': 'Conversation not found or access denied'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def delete_conversation(request, conversation_id):
    """Delete a conversation."""
    chat_service = ChatService()
    success = chat_service.delete_conversation(request.user, conversation_id)
    
    if success:
        return Response({
            'message': 'Conversation deleted successfully'
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'error': 'Conversation not found or access denied'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def clear_all_conversations(request):
    """Clear all conversations and folders for the authenticated user."""
    try:
        # Delete all conversations for the user
        conversations_deleted = Conversation.objects.filter(user=request.user).delete()[0]
        
        # Delete all folders for the user
        folders_deleted = Folder.objects.filter(user=request.user).delete()[0]
        
        return Response({
            'message': f'Successfully cleared {conversations_deleted} conversations and {folders_deleted} folders'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            'error': f'Failed to clear conversations and folders: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def export_conversation(request, conversation_id):
    """Export conversation data."""
    chat_service = ChatService()
    data = chat_service.export_conversation(request.user, conversation_id)
    
    if data:
        return Response(data, status=status.HTTP_200_OK)
    else:
        return Response({
            'error': 'Conversation not found or access denied'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def pin_conversation(request, conversation_id):
    """Pin or unpin a conversation."""
    try:
        conversation = Conversation.objects.get(
            id=conversation_id,
            user=request.user
        )
        
        is_pinned = request.data.get('is_pinned', True)
        conversation.is_pinned = is_pinned
        conversation.save(update_fields=['is_pinned'])
        
        action = 'pinned' if is_pinned else 'unpinned'
        return Response({
            'message': f'Conversation {action} successfully',
            'conversation': ConversationSerializer(conversation).data
        }, status=status.HTTP_200_OK)
        
    except Conversation.DoesNotExist:
        return Response({
            'error': 'Conversation not found or access denied'
        }, status=status.HTTP_404_NOT_FOUND)


class AdminChatAnalyticsView(APIView):
    """Admin-only endpoint for chat analytics."""
    
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        """Get comprehensive chat analytics."""
        # Total statistics
        total_conversations = Conversation.objects.count()
        total_messages = ChatMessage.objects.count()
        total_users_with_chats = Conversation.objects.values('user').distinct().count()
        
        # Token usage
        total_tokens = sum(
            msg.tokens_used or 0 for msg in ChatMessage.objects.all()
        )
        
        # Average response time
        assistant_messages = ChatMessage.objects.filter(
            message_type=ChatMessage.MessageType.ASSISTANT,
            response_time_ms__isnull=False
        )
        
        if assistant_messages.exists():
            avg_response_time = sum(
                msg.response_time_ms for msg in assistant_messages
            ) / assistant_messages.count()
        else:
            avg_response_time = 0
        
        # Template usage
        template_stats = []
        for template in ChatTemplate.objects.order_by('-usage_count')[:10]:
            template_stats.append({
                'name': template.name,
                'category': template.category,
                'usage_count': template.usage_count,
                'created_by': template.created_by.username if template.created_by else 'System'
            })
        
        # User activity
        top_users = []
        for conversation in Conversation.objects.values('user__username').annotate(
            conversation_count=models.Count('id'),
            message_count=models.Count('messages')
        ).order_by('-conversation_count')[:10]:
            top_users.append({
                'username': conversation['user__username'],
                'conversations': conversation['conversation_count'],
                'messages': conversation['message_count']
            })
        
        return Response({
            'overview': {
                'total_conversations': total_conversations,
                'total_messages': total_messages,
                'total_users_with_chats': total_users_with_chats,
                'total_tokens_used': total_tokens,
                'avg_response_time_ms': round(avg_response_time, 2)
            },
            'template_usage': template_stats,
            'top_users': top_users
        }, status=status.HTTP_200_OK)


class RAGConversationHistoryView(APIView):
    """Get conversation history in RAG format with current question and last 4 messages."""
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, conversation_id):
        """Get RAG-formatted conversation history."""
        # Verify user has access to this conversation
        if request.user.is_admin:
            conversation = get_object_or_404(Conversation, id=conversation_id)
        else:
            conversation = get_object_or_404(
                Conversation,
                id=conversation_id,
                user=request.user
            )
        
        # Get current question from request
        current_question = request.data.get('current_question', '')
        if not current_question:
            return Response({
                'error': 'current_question is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get last 4 messages from conversation (2 questions + 2 answers)
        last_messages = conversation.messages.all().order_by('-created_at')[:4]
        
        # Build RAG format array
        rag_messages = []
        
        # First element: current question
        rag_messages.append({
            'message_type': 'user',
            'content': current_question
        })
        
        # Add last 4 messages in reverse order (oldest first)
        for message in reversed(last_messages):
            rag_messages.append({
                'message_type': message.message_type,
                'content': message.content
            })
        
        # Serialize the response
        serializer = RAGMessageSerializer(rag_messages, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([])  # Explicitly allow public access
def download_rag_file(request, filename):
    """
    Download a file from RAG service through backend proxy.
    This is a public endpoint that doesn't require authentication.
    """
    try:
        # Get RAG file download URL from settings
        from django.conf import settings
        rag_file_download_url = getattr(settings, 'RAG_FILE_DOWNLOAD_URL', 'http://t8s4w4w8k8goos4gw0o4s8o8.84.46.243.247.sslip.io/files/download')
        
        # Construct the full URL
        file_url = f"{rag_file_download_url}/{filename}"
        
        # Log the download request (without user info since it's public)
        logger = logging.getLogger(__name__)
        logger.info(f"Public file download request: {filename}")
        
        # Make request to RAG service
        response = requests.get(file_url, timeout=30, stream=True)
        response.raise_for_status()
        
        # Create Django response with the file content
        django_response = HttpResponse(
            response.content,
            content_type=response.headers.get('content-type', 'application/octet-stream')
        )
        
        # Set appropriate headers for file download
        django_response['Content-Disposition'] = f'attachment; filename="{filename}"'
        django_response['Content-Length'] = response.headers.get('content-length', len(response.content))
        
        return django_response
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download file {filename}: {str(e)}")
        return Response(
            {'error': f'Failed to download file: {str(e)}'}, 
            status=status.HTTP_502_BAD_GATEWAY
        )
    except Exception as e:
        logger.error(f"Unexpected error downloading file {filename}: {str(e)}")
        return Response(
            {'error': 'An unexpected error occurred'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )