from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from .models import Conversation, ChatMessage, ChatTemplate


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'user', 'message_count', 'status_badge', 
        'is_pinned', 'created_at', 'updated_at'
    ]
    list_filter = [
        'is_archived', 'is_pinned', 'created_at', 'updated_at'
    ]
    search_fields = ['title', 'user__username', 'user__email']
    readonly_fields = [
        'id', 'created_at', 'updated_at'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'user', 'title', 'is_pinned')
        }),
        ('Status', {
            'fields': ('is_archived',)
        }),
        ('Analytics', {
            'fields': (
                'total_tokens', 'total_cost', 'average_response_time',
                'created_at', 'updated_at'
            )
        }),
    )
    
    def status_badge(self, obj):
        """Display conversation status with color coding"""
        if obj.is_archived:
            return format_html(
                '<span style="color: #666; font-weight: bold;">📁 Archived</span>'
            )
        return format_html(
            '<span style="color: #28a745; font-weight: bold;">💬 Active</span>'
        )
    status_badge.short_description = 'Status'
    
    def message_count(self, obj):
        """Display number of messages in conversation"""
        return obj.messages.count()
    message_count.short_description = 'Messages'
    
    actions = ['archive_conversations', 'unarchive_conversations']
    
    def archive_conversations(self, request, queryset):
        """Archive selected conversations"""
        updated = queryset.update(is_archived=True)
        self.message_user(
            request, 
            f'{updated} conversation(s) archived successfully.'
        )
    archive_conversations.short_description = 'Archive selected conversations'
    
    def unarchive_conversations(self, request, queryset):
        """Unarchive selected conversations"""
        updated = queryset.update(is_archived=False)
        self.message_user(
            request, 
            f'{updated} conversation(s) unarchived successfully.'
        )
    unarchive_conversations.short_description = 'Unarchive selected conversations'


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = [
        'conversation', 'message_type', 'content_preview', 
        'status_badge', 'tokens_used', 'response_time_display', 
        'created_at'
    ]
    list_filter = [
        'message_type', 'status', 'created_at', 'conversation__user'
    ]
    search_fields = [
        'content', 'conversation__title', 'conversation__user__username',
        'ai_model', 'error_message'
    ]
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'tokens_used', 
        'response_time_ms', 'model_used'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Message Information', {
            'fields': (
                'id', 'conversation', 'message_type', 'content'
            )
        }),
        ('AI Information', {
            'fields': (
                'model_used', 'tokens_used', 
                'response_time_ms', 'status'
            )
        }),
        ('Error Information', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
        ('User Feedback', {
            'fields': ('is_helpful', 'feedback_comment'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def content_preview(self, obj):
        """Display truncated content preview"""
        if len(obj.content) > 50:
            return obj.content[:50] + '...'
        return obj.content
    content_preview.short_description = 'Content'
    
    def status_badge(self, obj):
        """Display message status with color coding"""
        status_colors = {
            'pending': '#ffc107',
            'processing': '#17a2b8',
            'completed': '#28a745',
            'failed': '#dc3545'
        }
        color = status_colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.status.title()
        )
    status_badge.short_description = 'Status'
    
    def response_time_display(self, obj):
        """Display response time in a readable format"""
        if obj.response_time:
            return f'{obj.response_time:.2f}s'
        return '-'
    response_time_display.short_description = 'Response Time'
    
    def has_add_permission(self, request):
        """Disable manual message creation"""
        return False


@admin.register(ChatTemplate)
class ChatTemplateAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'category', 'created_by', 'is_public', 
        'usage_count', 'created_at'
    ]
    list_filter = ['category', 'is_public', 'created_at', 'created_by']
    search_fields = ['name', 'description', 'prompt', 'created_by__username']
    readonly_fields = ['id', 'usage_count', 'created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Template Information', {
            'fields': ('name', 'description', 'category', 'prompt')
        }),
        ('Settings', {
            'fields': ('is_public', 'created_by')
        }),
        ('Statistics', {
            'fields': ('usage_count',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    def save_model(self, request, obj, form, change):
        """Set created_by to current user if not set"""
        if not change and not obj.created_by:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
    
    actions = ['make_public', 'make_private']
    
    def make_public(self, request, queryset):
        """Make selected templates public"""
        updated = queryset.update(is_public=True)
        self.message_user(
            request, 
            f'{updated} template(s) made public successfully.'
        )
    make_public.short_description = 'Make selected templates public'
    
    def make_private(self, request, queryset):
        """Make selected templates private"""
        updated = queryset.update(is_public=False)
        self.message_user(
            request, 
            f'{updated} template(s) made private successfully.'
        )
    make_private.short_description = 'Make selected templates private'