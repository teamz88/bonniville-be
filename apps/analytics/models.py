import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey


class EventType(models.TextChoices):
    """Event type choices for analytics"""
    USER_LOGIN = 'user_login', 'User Login'
    USER_LOGOUT = 'user_logout', 'User Logout'
    USER_REGISTER = 'user_register', 'User Registration'
    CHAT_MESSAGE = 'chat_message', 'Chat Message'
    FILE_UPLOAD = 'file_upload', 'File Upload'
    FILE_DOWNLOAD = 'file_download', 'File Download'
    FILE_SHARE = 'file_share', 'File Share'
    SUBSCRIPTION_UPGRADE = 'subscription_upgrade', 'Subscription Upgrade'
    SUBSCRIPTION_CANCEL = 'subscription_cancel', 'Subscription Cancel'
    PAGE_VIEW = 'page_view', 'Page View'
    API_CALL = 'api_call', 'API Call'
    ERROR_OCCURRED = 'error_occurred', 'Error Occurred'
    FEATURE_USED = 'feature_used', 'Feature Used'


class AnalyticsEvent(models.Model):
    """Model for tracking analytics events"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Event information
    event_type = models.CharField(
        max_length=50,
        choices=EventType.choices
    )
    event_name = models.CharField(max_length=100)
    event_description = models.TextField(blank=True)
    
    # User information
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='analytics_events'
    )
    session_id = models.CharField(max_length=100, blank=True)
    
    # Request information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    referer = models.URLField(max_length=500, blank=True)
    
    # Event data
    properties = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    # Related object (generic foreign key)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    object_id = models.PositiveIntegerField(null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'analytics_events'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event_type', 'created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['session_id']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.event_name} - {self.user or 'Anonymous'} - {self.created_at}"


class UserActivity(models.Model):
    """Model for tracking daily user activity"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='daily_activities'
    )
    date = models.DateField()
    
    # Activity metrics
    login_count = models.IntegerField(default=0)
    chat_messages_sent = models.IntegerField(default=0)
    files_uploaded = models.IntegerField(default=0)
    files_downloaded = models.IntegerField(default=0)
    pages_visited = models.IntegerField(default=0)
    api_calls_made = models.IntegerField(default=0)
    
    # Time metrics (in seconds)
    total_session_time = models.IntegerField(default=0)
    active_time = models.IntegerField(default=0)
    
    # Feature usage
    features_used = models.JSONField(default=list, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_activities'
        unique_together = ['user', 'date']
        ordering = ['-date']
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['date']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.date}"


class SystemMetrics(models.Model):
    """Model for tracking system-wide metrics"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    date = models.DateField()
    
    # User metrics
    total_users = models.IntegerField(default=0)
    active_users = models.IntegerField(default=0)
    new_users = models.IntegerField(default=0)
    premium_users = models.IntegerField(default=0)
    
    # Content metrics
    total_conversations = models.IntegerField(default=0)
    total_messages = models.IntegerField(default=0)
    total_files = models.IntegerField(default=0)
    total_storage_used = models.BigIntegerField(default=0)  # in bytes
    
    # Performance metrics
    avg_response_time = models.FloatField(default=0.0)  # in seconds
    total_api_calls = models.IntegerField(default=0)
    error_rate = models.FloatField(default=0.0)  # percentage
    
    # Revenue metrics
    total_revenue = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    new_subscriptions = models.IntegerField(default=0)
    cancelled_subscriptions = models.IntegerField(default=0)
    
    # System health
    uptime_percentage = models.FloatField(default=100.0)
    
    # Additional metrics
    custom_metrics = models.JSONField(default=dict, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'system_metrics'
        unique_together = ['date']
        ordering = ['-date']
        indexes = [
            models.Index(fields=['date']),
        ]
    
    def __str__(self):
        return f"System Metrics - {self.date}"


class Report(models.Model):
    """Model for generated reports"""
    
    REPORT_TYPES = [
        ('user_activity', 'User Activity Report'),
        ('system_performance', 'System Performance Report'),
        ('revenue', 'Revenue Report'),
        ('content_usage', 'Content Usage Report'),
        ('error_analysis', 'Error Analysis Report'),
        ('custom', 'Custom Report'),
    ]
    
    REPORT_FORMATS = [
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('pdf', 'PDF'),
        ('excel', 'Excel'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Report information
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    report_format = models.CharField(max_length=20, choices=REPORT_FORMATS)
    
    # Report parameters
    start_date = models.DateField()
    end_date = models.DateField()
    filters = models.JSONField(default=dict, blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    
    # Report status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    progress = models.IntegerField(default=0)  # 0-100
    
    # Report data
    data = models.JSONField(default=dict, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.BigIntegerField(null=True, blank=True)
    
    # Error information
    error_message = models.TextField(blank=True)
    
    # User who requested the report
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='requested_reports'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'reports'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['requested_by', 'created_at']),
            models.Index(fields=['report_type', 'status']),
            models.Index(fields=['status']),
            models.Index(fields=['start_date', 'end_date']),
        ]
    
    def __str__(self):
        return f"{self.name} - {self.get_report_type_display()}"
    
    def mark_as_completed(self):
        """Mark report as completed"""
        self.status = 'completed'
        self.progress = 100
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'progress', 'completed_at'])
    
    def mark_as_failed(self, error_message):
        """Mark report as failed"""
        self.status = 'failed'
        self.error_message = error_message
        self.save(update_fields=['status', 'error_message'])
    
    @property
    def is_completed(self):
        """Check if report is completed"""
        return self.status == 'completed'
    
    @property
    def is_failed(self):
        """Check if report failed"""
        return self.status == 'failed'
    
    @property
    def duration_days(self):
        """Get report duration in days"""
        return (self.end_date - self.start_date).days + 1


class FeatureUsage(models.Model):
    """Model for tracking feature usage statistics"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Feature information
    feature_name = models.CharField(max_length=100)
    feature_category = models.CharField(max_length=50)
    
    # Usage statistics
    total_uses = models.IntegerField(default=0)
    unique_users = models.IntegerField(default=0)
    
    # Time period
    date = models.DateField()
    
    # Additional data
    usage_data = models.JSONField(default=dict, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'feature_usage'
        unique_together = ['feature_name', 'date']
        ordering = ['-date', 'feature_name']
        indexes = [
            models.Index(fields=['feature_name', 'date']),
            models.Index(fields=['feature_category', 'date']),
            models.Index(fields=['date']),
        ]
    
    def __str__(self):
        return f"{self.feature_name} - {self.date}"


class PaymentRecord(models.Model):
    """Model for tracking payment transactions"""
    
    PAYMENT_STATUS = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
        ('cancelled', 'Cancelled'),
    ]
    
    PAYMENT_TYPE = [
        ('subscription', 'Subscription'),
        ('upgrade', 'Upgrade'),
        ('renewal', 'Renewal'),
        ('lifetime', 'Lifetime'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='payment_records'
    )
    
    # Payment details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPE)
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='pending')
    
    # Subscription details
    subscription_type = models.CharField(max_length=20, blank=True)
    subscription_duration_days = models.IntegerField(null=True, blank=True)
    
    # Payment gateway details
    transaction_id = models.CharField(max_length=100, unique=True)
    gateway = models.CharField(max_length=50, blank=True)  # stripe, paypal, etc.
    gateway_response = models.JSONField(default=dict, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'payment_records'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['payment_type', 'created_at']),
            models.Index(fields=['status', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.amount} {self.currency} - {self.get_status_display()}"


class ErrorLog(models.Model):
    """Model for tracking application errors"""
    
    ERROR_LEVELS = [
        ('debug', 'Debug'),
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Error information
    level = models.CharField(max_length=20, choices=ERROR_LEVELS)
    message = models.TextField()
    exception_type = models.CharField(max_length=100, blank=True)
    stack_trace = models.TextField(blank=True)
    
    # Request information
    url = models.URLField(max_length=500, blank=True)
    method = models.CharField(max_length=10, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='error_logs'
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Additional context
    context = models.JSONField(default=dict, blank=True)
    
    # Resolution
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_errors'
    )
    resolution_notes = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'error_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['level', 'created_at']),
            models.Index(fields=['is_resolved', 'created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.get_level_display()}: {self.message[:50]}"
    
    def mark_as_resolved(self, user, notes=""):
        """Mark error as resolved"""
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.resolution_notes = notes
        self.save(update_fields=[
            'is_resolved', 'resolved_at', 'resolved_by', 'resolution_notes'
        ])