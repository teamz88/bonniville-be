from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.urls import reverse
from django.db.models import Count, Sum, Avg
from django.utils import timezone
from datetime import timedelta
import json

from .models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog
)


@admin.register(AnalyticsEvent)
class AnalyticsEventAdmin(admin.ModelAdmin):
    """Admin interface for analytics events"""
    list_display = [
        'event_name', 'event_type', 'user_display', 'ip_address',
        'created_at_display', 'has_properties'
    ]
    list_filter = [
        'event_type', 'created_at', 'user__is_staff', 'user__is_active'
    ]
    search_fields = [
        'event_name', 'event_description', 'user__username', 'user__email',
        'ip_address', 'session_id'
    ]
    readonly_fields = [
        'id', 'created_at', 'properties_display', 'metadata_display',
        'content_object_link'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Event Information', {
            'fields': (
                'event_type', 'event_name', 'event_description'
            )
        }),
        ('User & Session', {
            'fields': (
                'user', 'session_id', 'ip_address', 'user_agent', 'referer'
            )
        }),
        ('Data', {
            'fields': (
                'properties_display', 'metadata_display'
            ),
            'classes': ('collapse',)
        }),
        ('Related Object', {
            'fields': (
                'content_type', 'object_id', 'content_object_link'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at'),
            'classes': ('collapse',)
        })
    )
    
    def user_display(self, obj):
        """Display user information"""
        if obj.user:
            return f"{obj.user.username} ({obj.user.email})"
        return "Anonymous"
    user_display.short_description = "User"
    
    def created_at_display(self, obj):
        """Display formatted creation time"""
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')
    created_at_display.short_description = "Created"
    
    def has_properties(self, obj):
        """Check if event has properties"""
        return bool(obj.properties)
    has_properties.boolean = True
    has_properties.short_description = "Has Properties"
    
    def properties_display(self, obj):
        """Display formatted properties"""
        if obj.properties:
            return format_html(
                '<pre>{}</pre>',
                json.dumps(obj.properties, indent=2)
            )
        return "No properties"
    properties_display.short_description = "Properties"
    
    def metadata_display(self, obj):
        """Display formatted metadata"""
        if obj.metadata:
            return format_html(
                '<pre>{}</pre>',
                json.dumps(obj.metadata, indent=2)
            )
        return "No metadata"
    metadata_display.short_description = "Metadata"
    
    def content_object_link(self, obj):
        """Display link to related object"""
        if obj.content_object:
            try:
                url = reverse(
                    f'admin:{obj.content_type.app_label}_{obj.content_type.model}_change',
                    args=[obj.object_id]
                )
                return format_html(
                    '<a href="{}">{}</a>',
                    url,
                    str(obj.content_object)
                )
            except:
                return str(obj.content_object)
        return "No related object"
    content_object_link.short_description = "Related Object"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'content_type'
        )


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    """Admin interface for user activity"""
    list_display = [
        'user_display', 'date', 'login_count', 'chat_messages_sent',
        'files_uploaded', 'files_downloaded', 'session_time_display',
        'activity_score'
    ]
    list_filter = [
        'date', 'user__is_staff', 'user__is_active'
    ]
    search_fields = [
        'user__username', 'user__email'
    ]
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'activity_score',
        'session_time_display', 'active_time_display'
    ]
    date_hierarchy = 'date'
    ordering = ['-date', '-chat_messages_sent']
    
    fieldsets = (
        ('User & Date', {
            'fields': ('user', 'date')
        }),
        ('Activity Metrics', {
            'fields': (
                'login_count', 'chat_messages_sent', 'files_uploaded',
                'files_downloaded', 'pages_visited', 'api_calls_made'
            )
        }),
        ('Time Metrics', {
            'fields': (
                'total_session_time', 'session_time_display',
                'active_time', 'active_time_display'
            )
        }),
        ('Features', {
            'fields': ('features_used',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('id', 'created_at', 'updated_at', 'activity_score'),
            'classes': ('collapse',)
        })
    )
    
    def user_display(self, obj):
        """Display user information"""
        return f"{obj.user.username} ({obj.user.email})"
    user_display.short_description = "User"
    
    def session_time_display(self, obj):
        """Display formatted session time"""
        return self._format_duration(obj.total_session_time)
    session_time_display.short_description = "Session Time"
    
    def active_time_display(self, obj):
        """Display formatted active time"""
        return self._format_duration(obj.active_time)
    active_time_display.short_description = "Active Time"
    
    def activity_score(self, obj):
        """Calculate activity score"""
        score = (
            obj.login_count * 1 +
            obj.chat_messages_sent * 2 +
            obj.files_uploaded * 3 +
            obj.files_downloaded * 1 +
            obj.pages_visited * 0.5
        )
        return f"{score:.1f}"
    activity_score.short_description = "Activity Score"
    
    def _format_duration(self, seconds):
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes}m {seconds % 60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(SystemMetrics)
class SystemMetricsAdmin(admin.ModelAdmin):
    """Admin interface for system metrics"""
    list_display = [
        'date', 'total_users', 'active_users', 'new_users',
        'total_files', 'storage_used_display', 'error_rate_display',
        'uptime_display'
    ]
    list_filter = ['date']
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'storage_used_display',
        'error_rate_display', 'uptime_display', 'revenue_display'
    ]
    date_hierarchy = 'date'
    ordering = ['-date']
    
    fieldsets = (
        ('Date', {
            'fields': ('date',)
        }),
        ('User Metrics', {
            'fields': (
                'total_users', 'active_users', 'new_users', 'premium_users'
            )
        }),
        ('Content Metrics', {
            'fields': (
                'total_conversations', 'total_messages', 'total_files',
                'total_storage_used', 'storage_used_display'
            )
        }),
        ('Performance Metrics', {
            'fields': (
                'avg_response_time', 'total_api_calls', 'error_rate',
                'error_rate_display', 'uptime_percentage', 'uptime_display'
            )
        }),
        ('Revenue Metrics', {
            'fields': (
                'total_revenue', 'revenue_display', 'new_subscriptions',
                'cancelled_subscriptions'
            )
        }),
        ('Custom Metrics', {
            'fields': ('custom_metrics',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def storage_used_display(self, obj):
        """Display formatted storage size"""
        size = obj.total_storage_used
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    storage_used_display.short_description = "Storage Used"
    
    def error_rate_display(self, obj):
        """Display formatted error rate"""
        if obj.error_rate >= 10:
            color = 'red'
        elif obj.error_rate >= 5:
            color = 'orange'
        else:
            color = 'green'
        
        return format_html(
            '<span style="color: {};">{:.2f}%</span>',
            color,
            obj.error_rate
        )
    error_rate_display.short_description = "Error Rate"
    
    def uptime_display(self, obj):
        """Display formatted uptime"""
        if obj.uptime_percentage >= 99.9:
            color = 'green'
        elif obj.uptime_percentage >= 99:
            color = 'orange'
        else:
            color = 'red'
        
        return format_html(
            '<span style="color: {};">{:.2f}%</span>',
            color,
            obj.uptime_percentage
        )
    uptime_display.short_description = "Uptime"
    
    def revenue_display(self, obj):
        """Display formatted revenue"""
        return f"${obj.total_revenue:,.2f}"
    revenue_display.short_description = "Revenue"


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    """Admin interface for reports"""
    list_display = [
        'name', 'report_type', 'report_format', 'status_display',
        'progress_display', 'requested_by_display', 'created_at_display'
    ]
    list_filter = [
        'report_type', 'report_format', 'status', 'created_at'
    ]
    search_fields = [
        'name', 'description', 'requested_by__username', 'requested_by__email'
    ]
    readonly_fields = [
        'id', 'status', 'progress', 'data', 'file_path', 'file_size',
        'error_message', 'created_at', 'updated_at', 'completed_at',
        'duration_days', 'file_size_display', 'download_link'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    fieldsets = (
        ('Report Information', {
            'fields': (
                'name', 'description', 'report_type', 'report_format'
            )
        }),
        ('Date Range', {
            'fields': (
                'start_date', 'end_date', 'duration_days'
            )
        }),
        ('Configuration', {
            'fields': (
                'filters', 'parameters'
            ),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': (
                'status', 'progress', 'error_message'
            )
        }),
        ('Output', {
            'fields': (
                'file_path', 'file_size', 'file_size_display', 'download_link'
            )
        }),
        ('User & Timestamps', {
            'fields': (
                'requested_by', 'created_at', 'updated_at', 'completed_at'
            )
        }),
        ('Data', {
            'fields': ('data',),
            'classes': ('collapse',)
        })
    )
    
    def requested_by_display(self, obj):
        """Display user who requested the report"""
        return f"{obj.requested_by.username} ({obj.requested_by.email})"
    requested_by_display.short_description = "Requested By"
    
    def created_at_display(self, obj):
        """Display formatted creation time"""
        return obj.created_at.strftime('%Y-%m-%d %H:%M')
    created_at_display.short_description = "Created"
    
    def status_display(self, obj):
        """Display colored status"""
        colors = {
            'pending': 'gray',
            'processing': 'blue',
            'completed': 'green',
            'failed': 'red'
        }
        color = colors.get(obj.status, 'black')
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.status.title()
        )
    status_display.short_description = "Status"
    
    def progress_display(self, obj):
        """Display progress bar"""
        if obj.status == 'completed':
            color = 'green'
        elif obj.status == 'failed':
            color = 'red'
        elif obj.progress > 0:
            color = 'blue'
        else:
            color = 'gray'
        
        return format_html(
            '<div style="width: 100px; background-color: #f0f0f0; border-radius: 3px;">' +
            '<div style="width: {}%; background-color: {}; height: 20px; border-radius: 3px; text-align: center; color: white; font-size: 12px; line-height: 20px;">' +
            '{}%</div></div>',
            obj.progress,
            color,
            obj.progress
        )
    progress_display.short_description = "Progress"
    
    def duration_days(self, obj):
        """Calculate duration in days"""
        if obj.start_date and obj.end_date:
            return (obj.end_date - obj.start_date).days + 1
        return None
    duration_days.short_description = "Duration (days)"
    
    def file_size_display(self, obj):
        """Display formatted file size"""
        if not obj.file_size:
            return "No file"
        
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    file_size_display.short_description = "File Size"
    
    def download_link(self, obj):
        """Display download link"""
        if obj.status == 'completed' and obj.file_path:
            url = reverse('analytics:report-download', args=[obj.pk])
            return format_html(
                '<a href="{}" target="_blank">Download Report</a>',
                url
            )
        return "Not available"
    download_link.short_description = "Download"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('requested_by')


@admin.register(FeatureUsage)
class FeatureUsageAdmin(admin.ModelAdmin):
    """Admin interface for feature usage"""
    list_display = [
        'feature_name', 'feature_category', 'date', 'total_uses',
        'unique_users', 'usage_ratio'
    ]
    list_filter = [
        'feature_category', 'date'
    ]
    search_fields = [
        'feature_name', 'feature_category'
    ]
    readonly_fields = [
        'id', 'created_at', 'updated_at', 'usage_ratio'
    ]
    date_hierarchy = 'date'
    ordering = ['-date', '-total_uses']
    
    fieldsets = (
        ('Feature Information', {
            'fields': (
                'feature_name', 'feature_category', 'date'
            )
        }),
        ('Usage Statistics', {
            'fields': (
                'total_uses', 'unique_users', 'usage_ratio'
            )
        }),
        ('Usage Data', {
            'fields': ('usage_data',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def usage_ratio(self, obj):
        """Calculate usage ratio (uses per user)"""
        if obj.unique_users > 0:
            ratio = obj.total_uses / obj.unique_users
            return f"{ratio:.2f}"
        return "0.00"
    usage_ratio.short_description = "Uses/User"


@admin.register(ErrorLog)
class ErrorLogAdmin(admin.ModelAdmin):
    """Admin interface for error logs"""
    list_display = [
        'level_display', 'exception_type', 'message_preview',
        'user_display', 'url_display', 'resolved_display',
        'created_at_display'
    ]
    list_filter = [
        'level', 'is_resolved', 'exception_type', 'method', 'created_at'
    ]
    search_fields = [
        'message', 'exception_type', 'url', 'user__username',
        'user__email', 'ip_address'
    ]
    readonly_fields = [
        'id', 'created_at', 'stack_trace_display', 'context_display'
    ]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    
    actions = ['mark_resolved', 'mark_unresolved']
    
    fieldsets = (
        ('Error Information', {
            'fields': (
                'level', 'message', 'exception_type'
            )
        }),
        ('Request Information', {
            'fields': (
                'url', 'method', 'user', 'ip_address', 'user_agent'
            )
        }),
        ('Stack Trace', {
            'fields': ('stack_trace_display',),
            'classes': ('collapse',)
        }),
        ('Context', {
            'fields': ('context_display',),
            'classes': ('collapse',)
        }),
        ('Resolution', {
            'fields': (
                'is_resolved', 'resolved_at', 'resolved_by', 'resolution_notes'
            )
        }),
        ('Timestamps', {
            'fields': ('id', 'created_at'),
            'classes': ('collapse',)
        })
    )
    
    def level_display(self, obj):
        """Display colored error level"""
        colors = {
            'debug': 'gray',
            'info': 'blue',
            'warning': 'orange',
            'error': 'red',
            'critical': 'darkred'
        }
        color = colors.get(obj.level.lower(), 'black')
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.level.upper()
        )
    level_display.short_description = "Level"
    
    def message_preview(self, obj):
        """Display truncated message"""
        if len(obj.message) > 50:
            return f"{obj.message[:50]}..."
        return obj.message
    message_preview.short_description = "Message"
    
    def user_display(self, obj):
        """Display user information"""
        if obj.user:
            return f"{obj.user.username}"
        return "Anonymous"
    user_display.short_description = "User"
    
    def url_display(self, obj):
        """Display truncated URL"""
        if obj.url and len(obj.url) > 30:
            return f"{obj.url[:30]}..."
        return obj.url or "N/A"
    url_display.short_description = "URL"
    
    def resolved_display(self, obj):
        """Display resolution status"""
        if obj.is_resolved:
            return format_html(
                '<span style="color: green;">✓ Resolved</span>'
            )
        return format_html(
            '<span style="color: red;">✗ Unresolved</span>'
        )
    resolved_display.short_description = "Status"
    
    def created_at_display(self, obj):
        """Display formatted creation time"""
        return obj.created_at.strftime('%Y-%m-%d %H:%M')
    created_at_display.short_description = "Created"
    
    def stack_trace_display(self, obj):
        """Display formatted stack trace"""
        if obj.stack_trace:
            return format_html('<pre>{}</pre>', obj.stack_trace)
        return "No stack trace"
    stack_trace_display.short_description = "Stack Trace"
    
    def context_display(self, obj):
        """Display formatted context"""
        if obj.context:
            return format_html(
                '<pre>{}</pre>',
                json.dumps(obj.context, indent=2)
            )
        return "No context"
    context_display.short_description = "Context"
    
    def mark_resolved(self, request, queryset):
        """Mark selected errors as resolved"""
        updated = queryset.update(
            is_resolved=True,
            resolved_at=timezone.now(),
            resolved_by=request.user
        )
        self.message_user(
            request,
            f"{updated} error(s) marked as resolved."
        )
    mark_resolved.short_description = "Mark selected errors as resolved"
    
    def mark_unresolved(self, request, queryset):
        """Mark selected errors as unresolved"""
        updated = queryset.update(
            is_resolved=False,
            resolved_at=None,
            resolved_by=None,
            resolution_notes=''
        )
        self.message_user(
            request,
            f"{updated} error(s) marked as unresolved."
        )
    mark_unresolved.short_description = "Mark selected errors as unresolved"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'resolved_by'
        )