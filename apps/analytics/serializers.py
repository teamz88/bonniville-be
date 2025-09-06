from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import datetime, timedelta
from .models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog
)

User = get_user_model()


class AnalyticsEventSerializer(serializers.ModelSerializer):
    """Serializer for analytics events"""
    user_display = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = AnalyticsEvent
        fields = [
            'id', 'event_type', 'event_name', 'event_description',
            'user', 'user_display', 'session_id', 'ip_address',
            'user_agent', 'referer', 'properties', 'metadata',
            'created_at'
        ]
        read_only_fields = [
            'id', 'user_display', 'created_at'
        ]
    
    def validate_properties(self, value):
        """Validate properties field"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Properties must be a dictionary")
        return value
    
    def validate_metadata(self, value):
        """Validate metadata field"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Metadata must be a dictionary")
        return value


class CreateEventSerializer(serializers.Serializer):
    """Serializer for creating analytics events"""
    event_type = serializers.ChoiceField(
        choices=AnalyticsEvent._meta.get_field('event_type').choices
    )
    event_name = serializers.CharField(max_length=100)
    event_description = serializers.CharField(
        max_length=500, 
        required=False, 
        allow_blank=True
    )
    properties = serializers.DictField(required=False, default=dict)
    metadata = serializers.DictField(required=False, default=dict)
    
    def validate_properties(self, value):
        """Validate properties field"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Properties must be a dictionary")
        return value
    
    def validate_metadata(self, value):
        """Validate metadata field"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Metadata must be a dictionary")
        return value


class UserActivitySerializer(serializers.ModelSerializer):
    """Serializer for user activity"""
    user_display = serializers.CharField(source='user.username', read_only=True)
    total_session_time_display = serializers.SerializerMethodField()
    active_time_display = serializers.SerializerMethodField()
    
    class Meta:
        model = UserActivity
        fields = [
            'id', 'user', 'user_display', 'date', 'login_count',
            'chat_messages_sent', 'files_uploaded', 'files_downloaded',
            'pages_visited', 'api_calls_made', 'total_session_time',
            'total_session_time_display', 'active_time', 'active_time_display',
            'features_used', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user_display', 'total_session_time_display',
            'active_time_display', 'created_at', 'updated_at'
        ]
    
    def get_total_session_time_display(self, obj):
        """Get human readable session time"""
        return self._format_duration(obj.total_session_time)
    
    def get_active_time_display(self, obj):
        """Get human readable active time"""
        return self._format_duration(obj.active_time)
    
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


class SystemMetricsSerializer(serializers.ModelSerializer):
    """Serializer for system metrics"""
    total_storage_used_display = serializers.SerializerMethodField()
    
    class Meta:
        model = SystemMetrics
        fields = [
            'id', 'date', 'total_users', 'active_users', 'new_users',
            'premium_users', 'total_conversations', 'total_messages',
            'total_files', 'total_storage_used', 'total_storage_used_display',
            'avg_response_time', 'total_api_calls', 'error_rate',
            'total_revenue', 'new_subscriptions', 'cancelled_subscriptions',
            'uptime_percentage', 'custom_metrics', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'total_storage_used_display', 'created_at', 'updated_at'
        ]
    
    def get_total_storage_used_display(self, obj):
        """Get human readable storage size"""
        size = obj.total_storage_used
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


class ReportSerializer(serializers.ModelSerializer):
    """Serializer for reports"""
    requested_by_display = serializers.CharField(
        source='requested_by.username', 
        read_only=True
    )
    duration_days = serializers.IntegerField(read_only=True)
    file_size_display = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = [
            'id', 'name', 'description', 'report_type', 'report_format',
            'start_date', 'end_date', 'duration_days', 'filters', 'parameters',
            'status', 'progress', 'data', 'file_path', 'file_size',
            'file_size_display', 'error_message', 'requested_by',
            'requested_by_display', 'created_at', 'updated_at', 'completed_at'
        ]
        read_only_fields = [
            'id', 'requested_by_display', 'duration_days', 'file_size_display',
            'status', 'progress', 'data', 'file_path', 'file_size',
            'error_message', 'created_at', 'updated_at', 'completed_at'
        ]
    
    def get_file_size_display(self, obj):
        """Get human readable file size"""
        if not obj.file_size:
            return None
        
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def validate(self, attrs):
        """Validate report data"""
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError(
                    "Start date cannot be after end date"
                )
            
            # Check if date range is not too large (max 1 year)
            if (end_date - start_date).days > 365:
                raise serializers.ValidationError(
                    "Date range cannot exceed 365 days"
                )
            
            # Check if end date is not in the future
            if end_date > timezone.now().date():
                raise serializers.ValidationError(
                    "End date cannot be in the future"
                )
        
        return attrs


class CreateReportSerializer(serializers.ModelSerializer):
    """Serializer for creating reports"""
    
    class Meta:
        model = Report
        fields = [
            'name', 'description', 'report_type', 'report_format',
            'start_date', 'end_date', 'filters', 'parameters'
        ]
    
    def validate(self, attrs):
        """Validate report creation data"""
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError(
                    "Start date cannot be after end date"
                )
            
            # Check if date range is not too large (max 1 year)
            if (end_date - start_date).days > 365:
                raise serializers.ValidationError(
                    "Date range cannot exceed 365 days"
                )
            
            # Check if end date is not in the future
            if end_date > timezone.now().date():
                raise serializers.ValidationError(
                    "End date cannot be in the future"
                )
        
        return attrs


class FeatureUsageSerializer(serializers.ModelSerializer):
    """Serializer for feature usage"""
    
    class Meta:
        model = FeatureUsage
        fields = [
            'id', 'feature_name', 'feature_category', 'total_uses',
            'unique_users', 'date', 'usage_data', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ErrorLogSerializer(serializers.ModelSerializer):
    """Serializer for error logs"""
    user_display = serializers.CharField(source='user.username', read_only=True)
    resolved_by_display = serializers.CharField(
        source='resolved_by.username', 
        read_only=True
    )
    
    class Meta:
        model = ErrorLog
        fields = [
            'id', 'level', 'message', 'exception_type', 'stack_trace',
            'url', 'method', 'user', 'user_display', 'ip_address',
            'user_agent', 'context', 'is_resolved', 'resolved_at',
            'resolved_by', 'resolved_by_display', 'resolution_notes',
            'created_at'
        ]
        read_only_fields = [
            'id', 'user_display', 'resolved_by_display', 'created_at'
        ]


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics"""
    # User stats
    total_users = serializers.IntegerField()
    active_users_today = serializers.IntegerField()
    new_users_today = serializers.IntegerField()
    premium_users = serializers.IntegerField()
    
    # Content stats
    total_conversations = serializers.IntegerField()
    total_messages = serializers.IntegerField()
    total_files = serializers.IntegerField()
    total_storage_used = serializers.IntegerField()
    
    # Performance stats
    avg_response_time = serializers.FloatField()
    error_rate = serializers.FloatField()
    uptime_percentage = serializers.FloatField()
    
    # Revenue stats
    total_revenue = serializers.DecimalField(max_digits=10, decimal_places=2)
    monthly_revenue = serializers.DecimalField(max_digits=10, decimal_places=2)
    
    # Charts data
    user_growth_chart = serializers.ListField()
    revenue_chart = serializers.ListField()
    activity_chart = serializers.ListField()
    feature_usage_chart = serializers.ListField()


class AnalyticsFilterSerializer(serializers.Serializer):
    """Serializer for analytics filters"""
    start_date = serializers.DateField(required=False)
    end_date = serializers.DateField(required=False)
    user_id = serializers.IntegerField(required=False)
    event_type = serializers.ChoiceField(
        choices=AnalyticsEvent._meta.get_field('event_type').choices,
        required=False
    )
    
    def validate(self, attrs):
        """Validate filter data"""
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError(
                    "Start date cannot be after end date"
                )
            
            # Check if date range is not too large (max 1 year)
            if (end_date - start_date).days > 365:
                raise serializers.ValidationError(
                    "Date range cannot exceed 365 days"
                )
        
        return attrs