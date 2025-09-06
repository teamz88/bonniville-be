from rest_framework import serializers
from .models import Conversation, ChatMessage, ChatTemplate, Folder


class ChatMessageSerializer(serializers.ModelSerializer):
    """Serializer for chat messages."""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = ChatMessage
        fields = (
            'id', 'conversation', 'user', 'user_username',
            'message_type', 'content', 'status', 'sources',
            'tokens_used', 'model_used', 'response_time_ms',
            'error_message', 'is_helpful', 'feedback_comment',
            'created_at', 'updated_at'
        )
        read_only_fields = (
            'id', 'user', 'user_username', 'tokens_used',
            'model_used', 'response_time_ms', 'error_message',
            'created_at', 'updated_at'
        )
    
    def validate_content(self, value):
        """Validate message content."""
        if not value or not value.strip():
            raise serializers.ValidationError("Message content cannot be empty.")
        
        if len(value) > 10000:  # 10KB limit
            raise serializers.ValidationError("Message content is too long (max 10,000 characters).")
        
        return value.strip()


class FolderSerializer(serializers.ModelSerializer):
    """Serializer for folders."""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    conversation_count = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = Folder
        fields = (
            'id', 'user', 'user_username', 'name', 'description',
            'color', 'conversation_count', 'created_at', 'updated_at'
        )
        read_only_fields = (
            'id', 'user', 'user_username', 'conversation_count',
            'created_at', 'updated_at'
        )
    
    def validate_name(self, value):
        """Validate folder name."""
        if not value or not value.strip():
            raise serializers.ValidationError("Folder name cannot be empty.")
        
        if len(value) > 100:
            raise serializers.ValidationError("Folder name is too long (max 100 characters).")
        
        # Check for duplicate folder names for the same user
        user = self.context['request'].user
        if Folder.objects.filter(user=user, name=value.strip()).exclude(pk=self.instance.pk if self.instance else None).exists():
            raise serializers.ValidationError("A folder with this name already exists.")
        
        return value.strip()
    
    def validate_color(self, value):
        """Validate folder color."""
        if value and not value.startswith('#'):
            raise serializers.ValidationError("Color must be in hex format (e.g., #6B7280).")
        
        if value and len(value) != 7:
            raise serializers.ValidationError("Color must be a valid hex color (e.g., #6B7280).")
        
        return value


class ConversationSerializer(serializers.ModelSerializer):
    """Serializer for conversations."""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    folder_color = serializers.CharField(source='folder.color', read_only=True)
    last_message = serializers.SerializerMethodField()
    message_count = serializers.IntegerField(source='total_messages', read_only=True)
    
    class Meta:
        model = Conversation
        fields = (
            'id', 'user', 'user_username', 'folder', 'folder_name', 'folder_color',
            'title', 'is_archived', 'is_pinned', 'total_messages',
            'total_tokens_used', 'last_message', 'message_count',
            'created_at', 'updated_at'
        )
        read_only_fields = (
            'id', 'user', 'user_username', 'total_messages',
            'total_tokens_used', 'created_at', 'updated_at'
        )
    
    def get_last_message(self, obj):
        """Get the last message in the conversation."""
        last_message = obj.messages.last()
        if last_message:
            return {
                'id': last_message.id,
                'content': last_message.content[:100] + ('...' if len(last_message.content) > 100 else ''),
                'message_type': last_message.message_type,
                'created_at': last_message.created_at
            }
        return None


class ConversationDetailSerializer(ConversationSerializer):
    """Detailed serializer for conversations with messages."""
    
    messages = ChatMessageSerializer(many=True, read_only=True)
    
    class Meta(ConversationSerializer.Meta):
        fields = ConversationSerializer.Meta.fields + ('messages',)


class ChatRequestSerializer(serializers.Serializer):
    """Serializer for chat requests."""
    
    message = serializers.CharField(
        max_length=10000,
        help_text="User message content"
    )
    
    conversation_id = serializers.UUIDField(
        required=False,
        allow_null=True,
        help_text="Existing conversation ID (optional for new conversations)"
    )
    
    template_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text="Template ID to use for the message (optional)"
    )
    
    folder_id = serializers.UUIDField(
        required=False,
        allow_null=True,
        help_text="Folder ID to organize the conversation (optional)"
    )
    
    def validate_message(self, value):
        """Validate message content."""
        if not value or not value.strip():
            raise serializers.ValidationError("Message cannot be empty.")
        return value.strip()
    
    def validate_conversation_id(self, value):
        """Validate conversation exists and belongs to user."""
        if value:
            user = self.context['request'].user
            try:
                conversation = Conversation.objects.get(id=value, user=user)
                return value
            except Conversation.DoesNotExist:
                raise serializers.ValidationError("Conversation not found or access denied.")
        return value
    
    def validate_template_id(self, value):
        """Validate template exists and is accessible."""
        if value:
            user = self.context['request'].user
            try:
                template = ChatTemplate.objects.get(
                    id=value,
                    is_public=True
                )
                return value
            except ChatTemplate.DoesNotExist:
                # Check if user owns the template
                try:
                    template = ChatTemplate.objects.get(
                        id=value,
                        created_by=user
                    )
                    return value
                except ChatTemplate.DoesNotExist:
                    raise serializers.ValidationError("Template not found or access denied.")
        return value


class ChatResponseSerializer(serializers.Serializer):
    """Serializer for chat responses."""
    
    conversation_id = serializers.UUIDField()
    user_message = ChatMessageSerializer()
    assistant_message = ChatMessageSerializer()
    tokens_used = serializers.IntegerField()
    response_time_ms = serializers.IntegerField()


class MessageFeedbackSerializer(serializers.Serializer):
    """Serializer for message feedback."""
    
    is_helpful = serializers.BooleanField()
    comment = serializers.CharField(
        max_length=1000,
        required=False,
        allow_blank=True
    )


class ChatTemplateSerializer(serializers.ModelSerializer):
    """Serializer for chat templates."""
    
    created_by_username = serializers.CharField(
        source='created_by.username',
        read_only=True
    )
    
    class Meta:
        model = ChatTemplate
        fields = (
            'id', 'name', 'description', 'category',
            'prompt', 'is_public', 'created_by',
            'created_by_username', 'usage_count',
            'created_at', 'updated_at'
        )
        read_only_fields = (
            'id', 'created_by', 'created_by_username',
            'usage_count', 'created_at', 'updated_at'
        )
    
    def validate_name(self, value):
        """Validate template name uniqueness for user."""
        user = self.context['request'].user
        
        # Check if template with same name exists for this user
        queryset = ChatTemplate.objects.filter(
            name=value,
            created_by=user
        )
        
        # Exclude current instance if updating
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        
        if queryset.exists():
            raise serializers.ValidationError(
                "You already have a template with this name."
            )
        
        return value
    
    def create(self, validated_data):
        """Create template with current user as creator."""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class ConversationStatsSerializer(serializers.Serializer):
    """Serializer for conversation statistics."""
    
    total_conversations = serializers.IntegerField()
    total_messages = serializers.IntegerField()
    total_tokens_used = serializers.IntegerField()
    avg_messages_per_conversation = serializers.FloatField()
    avg_response_time_ms = serializers.FloatField()
    most_active_day = serializers.CharField()
    conversations_this_week = serializers.IntegerField()
    conversations_this_month = serializers.IntegerField()


class RAGMessageSerializer(serializers.Serializer):
    """Serializer for RAG-formatted messages."""
    
    message_type = serializers.CharField()
    content = serializers.CharField()