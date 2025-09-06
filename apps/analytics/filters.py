import django_filters
from django.db.models import Q
from django.contrib.auth import get_user_model
from .models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog, EventType
)

User = get_user_model()


class AnalyticsEventFilter(django_filters.FilterSet):
    """Filter for analytics events"""
    event_type = django_filters.ChoiceFilter(
        choices=EventType.choices,
        help_text="Filter by event type"
    )
    event_name = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by event name (case-insensitive)"
    )
    user = django_filters.ModelChoiceFilter(
        queryset=User.objects.all(),
        help_text="Filter by user"
    )
    user_username = django_filters.CharFilter(
        field_name='user__username',
        lookup_expr='icontains',
        help_text="Filter by username (case-insensitive)"
    )
    session_id = django_filters.CharFilter(
        lookup_expr='exact',
        help_text="Filter by session ID"
    )
    ip_address = django_filters.CharFilter(
        lookup_expr='exact',
        help_text="Filter by IP address"
    )
    date_from = django_filters.DateFilter(
        field_name='created_at',
        lookup_expr='date__gte',
        help_text="Filter events from this date (YYYY-MM-DD)"
    )
    date_to = django_filters.DateFilter(
        field_name='created_at',
        lookup_expr='date__lte',
        help_text="Filter events to this date (YYYY-MM-DD)"
    )
    datetime_from = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte',
        help_text="Filter events from this datetime (ISO format)"
    )
    datetime_to = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte',
        help_text="Filter events to this datetime (ISO format)"
    )
    # Removed search filter to avoid Meta.fields conflict
    has_user = django_filters.BooleanFilter(
        field_name='user',
        lookup_expr='isnull',
        exclude=True,
        help_text="Filter events that have a user associated"
    )
    
    class Meta:
        model = AnalyticsEvent
        fields = [
            'event_type', 'event_name', 'user', 'user_username',
            'session_id', 'ip_address', 'date_from', 'date_to',
            'datetime_from', 'datetime_to', 'has_user'
        ]
    
    # filter_search method removed - using DRF SearchFilter instead


class UserActivityFilter(django_filters.FilterSet):
    """Filter for user activity"""
    user = django_filters.ModelChoiceFilter(
        queryset=User.objects.all(),
        help_text="Filter by user"
    )
    user_username = django_filters.CharFilter(
        field_name='user__username',
        lookup_expr='icontains',
        help_text="Filter by username (case-insensitive)"
    )
    user_email = django_filters.CharFilter(
        field_name='user__email',
        lookup_expr='icontains',
        help_text="Filter by user email (case-insensitive)"
    )
    date_from = django_filters.DateFilter(
        field_name='date',
        lookup_expr='gte',
        help_text="Filter activities from this date (YYYY-MM-DD)"
    )
    date_to = django_filters.DateFilter(
        field_name='date',
        lookup_expr='lte',
        help_text="Filter activities to this date (YYYY-MM-DD)"
    )
    login_count_min = django_filters.NumberFilter(
        field_name='login_count',
        lookup_expr='gte',
        help_text="Minimum login count"
    )
    login_count_max = django_filters.NumberFilter(
        field_name='login_count',
        lookup_expr='lte',
        help_text="Maximum login count"
    )
    messages_min = django_filters.NumberFilter(
        field_name='chat_messages_sent',
        lookup_expr='gte',
        help_text="Minimum messages sent"
    )
    messages_max = django_filters.NumberFilter(
        field_name='chat_messages_sent',
        lookup_expr='lte',
        help_text="Maximum messages sent"
    )
    files_uploaded_min = django_filters.NumberFilter(
        field_name='files_uploaded',
        lookup_expr='gte',
        help_text="Minimum files uploaded"
    )
    files_uploaded_max = django_filters.NumberFilter(
        field_name='files_uploaded',
        lookup_expr='lte',
        help_text="Maximum files uploaded"
    )
    session_time_min = django_filters.NumberFilter(
        field_name='total_session_time',
        lookup_expr='gte',
        help_text="Minimum session time (seconds)"
    )
    session_time_max = django_filters.NumberFilter(
        field_name='total_session_time',
        lookup_expr='lte',
        help_text="Maximum session time (seconds)"
    )
    has_activity = django_filters.BooleanFilter(
        method='filter_has_activity',
        help_text="Filter users with any activity"
    )
    
    class Meta:
        model = UserActivity
        fields = [
            'user', 'user_username', 'user_email', 'date_from', 'date_to',
            'login_count_min', 'login_count_max', 'messages_min', 'messages_max',
            'files_uploaded_min', 'files_uploaded_max', 'session_time_min',
            'session_time_max', 'has_activity'
        ]
    
    def filter_has_activity(self, queryset, name, value):
        """Filter users with any activity"""
        if value:
            return queryset.filter(
                Q(login_count__gt=0) |
                Q(chat_messages_sent__gt=0) |
                Q(files_uploaded__gt=0) |
                Q(files_downloaded__gt=0) |
                Q(pages_visited__gt=0)
            )
        return queryset


class SystemMetricsFilter(django_filters.FilterSet):
    """Filter for system metrics"""
    date_from = django_filters.DateFilter(
        field_name='date',
        lookup_expr='gte',
        help_text="Filter metrics from this date (YYYY-MM-DD)"
    )
    date_to = django_filters.DateFilter(
        field_name='date',
        lookup_expr='lte',
        help_text="Filter metrics to this date (YYYY-MM-DD)"
    )
    users_min = django_filters.NumberFilter(
        field_name='total_users',
        lookup_expr='gte',
        help_text="Minimum total users"
    )
    users_max = django_filters.NumberFilter(
        field_name='total_users',
        lookup_expr='lte',
        help_text="Maximum total users"
    )
    active_users_min = django_filters.NumberFilter(
        field_name='active_users',
        lookup_expr='gte',
        help_text="Minimum active users"
    )
    active_users_max = django_filters.NumberFilter(
        field_name='active_users',
        lookup_expr='lte',
        help_text="Maximum active users"
    )
    error_rate_min = django_filters.NumberFilter(
        field_name='error_rate',
        lookup_expr='gte',
        help_text="Minimum error rate"
    )
    error_rate_max = django_filters.NumberFilter(
        field_name='error_rate',
        lookup_expr='lte',
        help_text="Maximum error rate"
    )
    response_time_min = django_filters.NumberFilter(
        field_name='avg_response_time',
        lookup_expr='gte',
        help_text="Minimum average response time"
    )
    response_time_max = django_filters.NumberFilter(
        field_name='avg_response_time',
        lookup_expr='lte',
        help_text="Maximum average response time"
    )
    uptime_min = django_filters.NumberFilter(
        field_name='uptime_percentage',
        lookup_expr='gte',
        help_text="Minimum uptime percentage"
    )
    uptime_max = django_filters.NumberFilter(
        field_name='uptime_percentage',
        lookup_expr='lte',
        help_text="Maximum uptime percentage"
    )
    
    class Meta:
        model = SystemMetrics
        fields = [
            'date_from', 'date_to', 'users_min', 'users_max',
            'active_users_min', 'active_users_max', 'error_rate_min',
            'error_rate_max', 'response_time_min', 'response_time_max',
            'uptime_min', 'uptime_max'
        ]


class ReportFilter(django_filters.FilterSet):
    """Filter for reports"""
    report_type = django_filters.ChoiceFilter(
        choices=Report._meta.get_field('report_type').choices,
        help_text="Filter by report type"
    )
    report_format = django_filters.ChoiceFilter(
        choices=Report._meta.get_field('report_format').choices,
        help_text="Filter by report format"
    )
    status = django_filters.ChoiceFilter(
        choices=Report._meta.get_field('status').choices,
        help_text="Filter by report status"
    )
    requested_by = django_filters.ModelChoiceFilter(
        queryset=User.objects.all(),
        help_text="Filter by user who requested the report"
    )
    requested_by_username = django_filters.CharFilter(
        field_name='requested_by__username',
        lookup_expr='icontains',
        help_text="Filter by requester username (case-insensitive)"
    )
    name = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by report name (case-insensitive)"
    )
    created_from = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte',
        help_text="Filter reports created from this datetime"
    )
    created_to = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte',
        help_text="Filter reports created to this datetime"
    )
    completed_from = django_filters.DateTimeFilter(
        field_name='completed_at',
        lookup_expr='gte',
        help_text="Filter reports completed from this datetime"
    )
    completed_to = django_filters.DateTimeFilter(
        field_name='completed_at',
        lookup_expr='lte',
        help_text="Filter reports completed to this datetime"
    )
    date_range_from = django_filters.DateFilter(
        field_name='start_date',
        lookup_expr='gte',
        help_text="Filter by report start date range"
    )
    date_range_to = django_filters.DateFilter(
        field_name='end_date',
        lookup_expr='lte',
        help_text="Filter by report end date range"
    )
    progress_min = django_filters.NumberFilter(
        field_name='progress',
        lookup_expr='gte',
        help_text="Minimum progress percentage"
    )
    progress_max = django_filters.NumberFilter(
        field_name='progress',
        lookup_expr='lte',
        help_text="Maximum progress percentage"
    )
    
    class Meta:
        model = Report
        fields = [
            'report_type', 'report_format', 'status', 'requested_by',
            'requested_by_username', 'name', 'created_from', 'created_to',
            'completed_from', 'completed_to', 'date_range_from', 'date_range_to',
            'progress_min', 'progress_max'
        ]


class FeatureUsageFilter(django_filters.FilterSet):
    """Filter for feature usage"""
    feature_name = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by feature name (case-insensitive)"
    )
    feature_category = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by feature category (case-insensitive)"
    )
    date_from = django_filters.DateFilter(
        field_name='date',
        lookup_expr='gte',
        help_text="Filter usage from this date (YYYY-MM-DD)"
    )
    date_to = django_filters.DateFilter(
        field_name='date',
        lookup_expr='lte',
        help_text="Filter usage to this date (YYYY-MM-DD)"
    )
    uses_min = django_filters.NumberFilter(
        field_name='total_uses',
        lookup_expr='gte',
        help_text="Minimum total uses"
    )
    uses_max = django_filters.NumberFilter(
        field_name='total_uses',
        lookup_expr='lte',
        help_text="Maximum total uses"
    )
    users_min = django_filters.NumberFilter(
        field_name='unique_users',
        lookup_expr='gte',
        help_text="Minimum unique users"
    )
    users_max = django_filters.NumberFilter(
        field_name='unique_users',
        lookup_expr='lte',
        help_text="Maximum unique users"
    )
    
    class Meta:
        model = FeatureUsage
        fields = [
            'feature_name', 'feature_category', 'date_from', 'date_to',
            'uses_min', 'uses_max', 'users_min', 'users_max'
        ]


class ErrorLogFilter(django_filters.FilterSet):
    """Filter for error logs"""
    level = django_filters.ChoiceFilter(
        choices=ErrorLog._meta.get_field('level').choices,
        help_text="Filter by error level"
    )
    exception_type = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by exception type (case-insensitive)"
    )
    url = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by URL (case-insensitive)"
    )
    method = django_filters.ChoiceFilter(
        choices=ErrorLog._meta.get_field('method').choices,
        help_text="Filter by HTTP method"
    )
    user = django_filters.ModelChoiceFilter(
        queryset=User.objects.all(),
        help_text="Filter by user"
    )
    user_username = django_filters.CharFilter(
        field_name='user__username',
        lookup_expr='icontains',
        help_text="Filter by username (case-insensitive)"
    )
    ip_address = django_filters.CharFilter(
        lookup_expr='exact',
        help_text="Filter by IP address"
    )
    is_resolved = django_filters.BooleanFilter(
        help_text="Filter by resolution status"
    )
    resolved_by = django_filters.ModelChoiceFilter(
        queryset=User.objects.all(),
        help_text="Filter by user who resolved the error"
    )
    date_from = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte',
        help_text="Filter errors from this datetime"
    )
    date_to = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte',
        help_text="Filter errors to this datetime"
    )
    resolved_from = django_filters.DateTimeFilter(
        field_name='resolved_at',
        lookup_expr='gte',
        help_text="Filter by resolution datetime from"
    )
    resolved_to = django_filters.DateTimeFilter(
        field_name='resolved_at',
        lookup_expr='lte',
        help_text="Filter by resolution datetime to"
    )
    # Removed search filter to avoid Meta.fields conflict
    has_stack_trace = django_filters.BooleanFilter(
        field_name='stack_trace',
        lookup_expr='isnull',
        exclude=True,
        help_text="Filter errors that have stack trace"
    )
    has_user = django_filters.BooleanFilter(
        field_name='user',
        lookup_expr='isnull',
        exclude=True,
        help_text="Filter errors that have a user associated"
    )
    
    class Meta:
        model = ErrorLog
        fields = [
            'level', 'exception_type', 'url', 'method', 'user', 'user_username',
            'ip_address', 'is_resolved', 'resolved_by', 'date_from', 'date_to',
            'resolved_from', 'resolved_to', 'has_stack_trace', 'has_user'
        ]
    
    # filter_search method removed - using DRF SearchFilter instead


class DateRangeFilter(django_filters.FilterSet):
    """Base filter for date range filtering"""
    date_from = django_filters.DateFilter(
        method='filter_date_from',
        help_text="Filter from this date (YYYY-MM-DD)"
    )
    date_to = django_filters.DateFilter(
        method='filter_date_to',
        help_text="Filter to this date (YYYY-MM-DD)"
    )
    last_days = django_filters.NumberFilter(
        method='filter_last_days',
        help_text="Filter last N days"
    )
    this_week = django_filters.BooleanFilter(
        method='filter_this_week',
        help_text="Filter this week"
    )
    this_month = django_filters.BooleanFilter(
        method='filter_this_month',
        help_text="Filter this month"
    )
    this_year = django_filters.BooleanFilter(
        method='filter_this_year',
        help_text="Filter this year"
    )
    
    def filter_date_from(self, queryset, name, value):
        """Override in subclasses"""
        return queryset
    
    def filter_date_to(self, queryset, name, value):
        """Override in subclasses"""
        return queryset
    
    def filter_last_days(self, queryset, name, value):
        """Override in subclasses"""
        return queryset
    
    def filter_this_week(self, queryset, name, value):
        """Override in subclasses"""
        return queryset
    
    def filter_this_month(self, queryset, name, value):
        """Override in subclasses"""
        return queryset
    
    def filter_this_year(self, queryset, name, value):
        """Override in subclasses"""
        return queryset