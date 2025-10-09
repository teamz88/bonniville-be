from django.urls import path
from . import views

app_name = 'chat'

urlpatterns = [
    # Main chat endpoint
    path('', views.ChatView.as_view(), name='chat'),
    path('stream/', views.ChatStreamView.as_view(), name='chat_stream'),
    
    # Conversation management
    path('conversations/', views.ConversationListView.as_view(), name='conversation_list'),
    path('conversations/<uuid:pk>/', views.ConversationDetailView.as_view(), name='conversation_detail'),
    path('conversations/<uuid:conversation_id>/history/', views.ConversationHistoryView.as_view(), name='conversation_history'),
    path('conversations/<uuid:conversation_id>/history', views.ConversationHistoryView.as_view(), name='conversation_history_no_slash'),
    path('conversations/<uuid:conversation_id>/archive/', views.archive_conversation, name='archive_conversation'),
    path('conversations/<uuid:conversation_id>/delete/', views.delete_conversation, name='delete_conversation'),
    path('conversations/<uuid:conversation_id>/export/', views.export_conversation, name='export_conversation'),
    path('conversations/<uuid:conversation_id>/pin/', views.pin_conversation, name='pin_conversation'),
    path('conversations/clear-all/', views.clear_all_conversations, name='clear_all_conversations'),
    
    # Message feedback
    path('messages/<uuid:message_id>/feedback/', views.MessageFeedbackView.as_view(), name='message_feedback'),
    
    # New feedback APIs
    path('feedback/', views.FeedbackView.as_view(), name='feedback'),
    path('feedbacks/', views.FeedbackListView.as_view(), name='feedbacks'),
    path('feedback/analytics/', views.RAGFeedbackAnalyticsView.as_view(), name='rag_feedback_analytics'),
    
    # Templates
    path('templates/', views.ChatTemplateListView.as_view(), name='template_list'),
    path('templates/<int:pk>/', views.ChatTemplateDetailView.as_view(), name='template_detail'),
    
    # Folders
    path('folders/', views.FolderListView.as_view(), name='folder_list'),
    path('folders/<uuid:pk>/', views.FolderDetailView.as_view(), name='folder_detail'),
    path('folders/<uuid:folder_id>/conversations/', views.folder_conversations, name='folder_conversations'),
    path('conversations/<uuid:conversation_id>/move/', views.move_conversation_to_folder, name='move_conversation_to_folder'),
    
    # Statistics and analytics
    path('stats/', views.conversation_stats, name='conversation_stats'),
    path('admin/analytics/', views.AdminChatAnalyticsView.as_view(), name='admin_analytics'),
    
    # RAG formatted conversation history
    path('conversations/<uuid:conversation_id>/rag-history/', views.RAGConversationHistoryView.as_view(), name='rag_conversation_history'),
    path('conversations/<uuid:conversation_id>/rag-history', views.RAGConversationHistoryView.as_view(), name='rag_conversation_history_no_slash'),

    # RAG file download
    path('files/download/<str:filename>/', views.download_rag_file, name='download_rag_file'),
]