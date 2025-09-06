from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid


class Folder(models.Model):
    """Model to represent conversation folders for organization."""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='folders'
    )
    
    name = models.CharField(
        max_length=100,
        help_text="Folder name"
    )
    
    description = models.TextField(
        blank=True,
        help_text="Optional folder description"
    )
    
    color = models.CharField(
        max_length=7,
        default='#6B7280',
        help_text="Folder color in hex format"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'chat_folders'
        verbose_name = 'Folder'
        verbose_name_plural = 'Folders'
        ordering = ['name']
        unique_together = ['user', 'name']
        indexes = [
            models.Index(fields=['user', 'name']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.name}"
    
    @property
    def conversation_count(self):
        """Return the number of conversations in this folder."""
        return self.conversations.count()


class Conversation(models.Model):
    """Model to represent a chat conversation."""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='conversations'
    )
    
    folder = models.ForeignKey(
        Folder,
        on_delete=models.SET_NULL,
        related_name='conversations',
        null=True,
        blank=True,
        help_text="Folder containing this conversation"
    )
    
    title = models.CharField(
        max_length=200,
        blank=True,
        help_text="Conversation title (auto-generated from first message)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Conversation metadata
    is_archived = models.BooleanField(
        default=False,
        help_text="Whether conversation is archived"
    )
    
    is_pinned = models.BooleanField(
        default=False,
        help_text="Whether conversation is pinned"
    )
    
    # Analytics
    total_messages = models.PositiveIntegerField(
        default=0,
        help_text="Total number of messages in conversation"
    )
    
    total_tokens_used = models.PositiveIntegerField(
        default=0,
        help_text="Total tokens used in this conversation"
    )
    
    class Meta:
        db_table = 'chat_conversations'
        verbose_name = 'Conversation'
        verbose_name_plural = 'Conversations'
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['user', '-updated_at']),
            models.Index(fields=['user', 'is_archived']),
            models.Index(fields=['user', 'is_pinned']),
            models.Index(fields=['user', 'folder']),
            models.Index(fields=['folder', '-updated_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.title or 'Untitled'}"
    
    def save(self, *args, **kwargs):
        # Auto-generate title from first message if not set
        if not self.title and self.pk:
            first_message = self.messages.filter(
                message_type=ChatMessage.MessageType.USER
            ).first()
            if first_message:
                # Use first 50 characters of the first user message
                self.title = first_message.content[:50]
                if len(first_message.content) > 50:
                    self.title += "..."
        
        super().save(*args, **kwargs)
    
    def update_stats(self):
        """Update conversation statistics."""
        self.total_messages = self.messages.count()
        self.total_tokens_used = sum(
            msg.tokens_used or 0 for msg in self.messages.all()
        )
        self.save(update_fields=['total_messages', 'total_tokens_used'])


class ChatMessage(models.Model):
    """Model to represent individual chat messages."""
    
    class MessageType(models.TextChoices):
        USER = 'user', 'User'
        ASSISTANT = 'assistant', 'Assistant'
        SYSTEM = 'system', 'System'
    
    class MessageStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name='messages'
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='chat_messages'
    )
    
    message_type = models.CharField(
        max_length=10,
        choices=MessageType.choices,
        help_text="Type of message (user, assistant, system)"
    )
    
    content = models.TextField(
        help_text="Message content"
    )
    
    # Message metadata
    status = models.CharField(
        max_length=10,
        choices=MessageStatus.choices,
        default=MessageStatus.COMPLETED,
        help_text="Message processing status"
    )
    
    # AI-related fields
    tokens_used = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Number of tokens used for this message"
    )
    
    model_used = models.CharField(
        max_length=100,
        blank=True,
        help_text="AI model used to generate response"
    )
    
    response_time_ms = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Response time in milliseconds"
    )
    
    # Error handling
    error_message = models.TextField(
        blank=True,
        help_text="Error message if processing failed"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # User feedback
    is_helpful = models.BooleanField(
        null=True,
        blank=True,
        help_text="User feedback on message helpfulness"
    )
    
    feedback_comment = models.TextField(
        blank=True,
        help_text="User feedback comment"
    )
    
    # Sources field for RAG responses
    sources = models.JSONField(
        default=list,
        blank=True,
        help_text="List of source documents used for this response"
    )
    
    class Meta:
        db_table = 'chat_messages'
        verbose_name = 'Chat Message'
        verbose_name_plural = 'Chat Messages'
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['conversation', 'created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['message_type', 'status']),
        ]
    
    def __str__(self):
        return f"{self.message_type} - {self.content[:50]}..."
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        
        # Update conversation stats when message is saved
        if self.conversation_id:
            self.conversation.updated_at = timezone.now()
            self.conversation.save(update_fields=['updated_at'])
    
    @property
    def is_from_user(self):
        """Check if message is from user."""
        return self.message_type == self.MessageType.USER
    
    @property
    def is_from_assistant(self):
        """Check if message is from assistant."""
        return self.message_type == self.MessageType.ASSISTANT
    
    def mark_as_helpful(self, helpful=True, comment=""):
        """Mark message as helpful or not helpful."""
        self.is_helpful = helpful
        self.feedback_comment = comment
        self.save(update_fields=['is_helpful', 'feedback_comment'])


class ChatTemplate(models.Model):
    """Model for predefined chat templates/prompts."""
    
    class TemplateCategory(models.TextChoices):
        GENERAL = 'general', 'General'
        BUSINESS = 'business', 'Business'
        TECHNICAL = 'technical', 'Technical'
        CREATIVE = 'creative', 'Creative'
        EDUCATIONAL = 'educational', 'Educational'
    
    name = models.CharField(
        max_length=100,
        help_text="Template name"
    )
    
    description = models.TextField(
        help_text="Template description"
    )
    
    category = models.CharField(
        max_length=20,
        choices=TemplateCategory.choices,
        default=TemplateCategory.GENERAL
    )
    
    prompt = models.TextField(
        help_text="Template prompt text"
    )
    
    # Access control
    is_public = models.BooleanField(
        default=True,
        help_text="Whether template is available to all users"
    )
    
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_templates',
        null=True,
        blank=True
    )
    
    # Usage statistics
    usage_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times template has been used"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'chat_templates'
        verbose_name = 'Chat Template'
        verbose_name_plural = 'Chat Templates'
        ordering = ['-usage_count', 'name']
        indexes = [
            models.Index(fields=['category', 'is_public']),
            models.Index(fields=['-usage_count']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.get_category_display()})"
    
    def increment_usage(self):
        """Increment usage count."""
        self.usage_count += 1
        self.save(update_fields=['usage_count'])