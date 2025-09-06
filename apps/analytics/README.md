# Analytics Application

A comprehensive analytics and monitoring system for the AI Agent platform.

## Features

### Core Analytics
- **Event Tracking**: Track user interactions, system events, and custom analytics events
- **User Activity Monitoring**: Monitor user login patterns, message activity, file uploads, and session duration
- **System Metrics**: Track system performance, user counts, storage usage, and error rates
- **Feature Usage Analytics**: Monitor which features are being used and by how many users

### Reporting System
- **Automated Reports**: Generate reports for user activity, system metrics, feature usage, and error logs
- **Multiple Formats**: Support for JSON and CSV export formats
- **Scheduled Generation**: Reports can be generated on-demand or scheduled
- **Progress Tracking**: Monitor report generation progress and status

### Error Tracking
- **Comprehensive Error Logging**: Capture exceptions, HTTP errors, and custom error events
- **Error Analytics**: Track error frequency, resolution status, and trends
- **Stack Trace Capture**: Full stack trace and context information for debugging
- **Resolution Tracking**: Mark errors as resolved and track who resolved them

### Dashboard & Statistics
- **Real-time Dashboard**: Get overview statistics for system health and user activity
- **User Activity Stats**: Detailed statistics for individual users (admin only)
- **Error Statistics**: Error frequency and trend analysis
- **System Health Monitoring**: Monitor system uptime, response times, and performance metrics

## API Endpoints

### Analytics Events
- `GET /api/analytics/events/` - List analytics events
- `POST /api/analytics/events/` - Create analytics event
- `POST /api/analytics/track/` - Track custom event

### User Activity
- `GET /api/analytics/user-activity/` - List user activity
- `GET /api/analytics/user-activity/stats/` - Get user activity statistics

### System Metrics
- `GET /api/analytics/system-metrics/` - List system metrics
- `POST /api/analytics/system-metrics/generate/` - Generate metrics for specific date
- `GET /api/analytics/system/health/` - Get system health status

### Reports
- `GET /api/analytics/reports/` - List reports
- `POST /api/analytics/reports/` - Create new report
- `GET /api/analytics/reports/{id}/` - Get report details
- `GET /api/analytics/reports/{id}/download/` - Download completed report

### Feature Usage
- `GET /api/analytics/feature-usage/` - List feature usage statistics

### Error Logs
- `GET /api/analytics/errors/` - List error logs
- `GET /api/analytics/errors/{id}/` - Get error details
- `PATCH /api/analytics/errors/{id}/` - Update error (mark as resolved)
- `POST /api/analytics/errors/log/` - Log new error
- `GET /api/analytics/errors/stats/` - Get error statistics

### Dashboard
- `GET /api/analytics/dashboard/stats/` - Get dashboard statistics

## Models

### AnalyticsEvent
Tracks user interactions and system events with metadata.

### UserActivity
Daily aggregated user activity metrics including logins, messages, uploads, and session time.

### SystemMetrics
Daily system-wide metrics including user counts, performance data, and resource usage.

### Report
Report generation requests with progress tracking and file management.

### FeatureUsage
Daily feature usage statistics tracking which features are being used.

### ErrorLog
Comprehensive error logging with stack traces, context, and resolution tracking.

## Services

### AnalyticsService
Core service for tracking events, updating user activity, and generating statistics.

### ReportService
Handles report generation for different data types with progress tracking.

### ErrorTrackingService
Manages error logging, statistics, and trend analysis.

## Management Commands

### generate_system_metrics
Generate system metrics for specific dates or date ranges.

```bash
python manage.py generate_system_metrics --date 2024-01-01
python manage.py generate_system_metrics --start-date 2024-01-01 --end-date 2024-01-31
python manage.py generate_system_metrics --force  # Regenerate existing metrics
```

### cleanup_analytics
Clean up old analytics data based on retention policies.

```bash
python manage.py cleanup_analytics --days 365  # Keep last 365 days
python manage.py cleanup_analytics --dry-run   # Preview what would be deleted
python manage.py cleanup_analytics --events-days 90 --metrics-days 730  # Different retention per type
```

## Permissions

- **Regular Users**: Can view their own analytics data and create events
- **Admin Users**: Can view all analytics data, generate reports, manage errors, and access system metrics

## Filtering & Search

All list endpoints support advanced filtering:
- Date range filtering
- User-specific filtering
- Event type and status filtering
- Search across relevant text fields
- Numerical range filtering for metrics

## Installation

1. The analytics app is already included in `INSTALLED_APPS`
2. Run migrations: `python manage.py migrate analytics`
3. The app is ready to use!

## Usage Examples

### Track a Custom Event
```python
from apps.analytics.services import AnalyticsService

AnalyticsService.track_event(
    user=request.user,
    event_type='user_action',
    event_name='feature_used',
    properties={'feature': 'chat', 'action': 'send_message'},
    request=request
)
```

### Log an Error
```python
from apps.analytics.services import ErrorTrackingService

ErrorTrackingService.log_error(
    level='ERROR',
    message='Database connection failed',
    exception_type='DatabaseError',
    stack_trace=traceback.format_exc(),
    request=request
)
```

### Generate a Report
```python
from apps.analytics.services import ReportService

report = ReportService.create_report(
    report_type='user_activity',
    requester=request.user,
    name='Monthly User Activity Report',
    parameters={'start_date': '2024-01-01', 'end_date': '2024-01-31'}
)
```