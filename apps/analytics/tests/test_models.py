from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from datetime import date, timedelta
import json

from apps.analytics.models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog, EventType
)
from apps.chat.models import Conversation

User = get_user_model()


class AnalyticsEventModelTest(TestCase):
    """Test cases for AnalyticsEvent model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.conversation = Conversation.objects.create(
            user=self.user,
            title='Test Conversation'
        )
    
    def test_create_analytics_event(self):
        """Test creating an analytics event"""
        event = AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='user_login',
            event_description='User logged in',
            user=self.user,
            session_id='test-session-123',
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0 Test Browser',
            properties={'login_method': 'email'},
            metadata={'source': 'web'}
        )
        
        self.assertEqual(event.event_type, EventType.USER_LOGIN)
        self.assertEqual(event.event_name, 'user_login')
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.session_id, 'test-session-123')
        self.assertEqual(event.properties['login_method'], 'email')
        self.assertEqual(event.metadata['source'], 'web')
    
    def test_analytics_event_with_content_object(self):
        """Test analytics event with related content object"""
        event = AnalyticsEvent.objects.create(
            event_type=EventType.CHAT_MESSAGE,
            event_name='message_sent',
            user=self.user,
            content_object=self.conversation
        )
        
        self.assertEqual(event.content_object, self.conversation)
        self.assertEqual(event.object_id, str(self.conversation.id))
        self.assertEqual(
            event.content_type,
            ContentType.objects.get_for_model(Conversation)
        )
    
    def test_analytics_event_str_representation(self):
        """Test string representation of analytics event"""
        event = AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='user_login',
            user=self.user
        )
        
        expected_str = f"user_login by {self.user.username}"
        self.assertEqual(str(event), expected_str)
    
    def test_analytics_event_ordering(self):
        """Test analytics events are ordered by creation time"""
        event1 = AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login1',
            user=self.user
        )
        event2 = AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login2',
            user=self.user
        )
        
        events = list(AnalyticsEvent.objects.all())
        self.assertEqual(events[0], event2)  # Most recent first
        self.assertEqual(events[1], event1)


class UserActivityModelTest(TestCase):
    """Test cases for UserActivity model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.today = date.today()
    
    def test_create_user_activity(self):
        """Test creating user activity record"""
        activity = UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=3,
            chat_messages_sent=15,
            files_uploaded=2,
            files_downloaded=5,
            pages_visited=25,
            api_calls_made=50,
            total_session_time=3600,  # 1 hour
            active_time=2400,  # 40 minutes
            features_used=['chat', 'file_upload', 'analytics']
        )
        
        self.assertEqual(activity.user, self.user)
        self.assertEqual(activity.date, self.today)
        self.assertEqual(activity.login_count, 3)
        self.assertEqual(activity.chat_messages_sent, 15)
        self.assertEqual(activity.total_session_time, 3600)
        self.assertEqual(activity.features_used, ['chat', 'file_upload', 'analytics'])
    
    def test_user_activity_str_representation(self):
        """Test string representation of user activity"""
        activity = UserActivity.objects.create(
            user=self.user,
            date=self.today
        )
        
        expected_str = f"{self.user.username} - {self.today}"
        self.assertEqual(str(activity), expected_str)
    
    def test_user_activity_unique_constraint(self):
        """Test unique constraint on user and date"""
        UserActivity.objects.create(
            user=self.user,
            date=self.today
        )
        
        # Creating another activity for same user and date should raise error
        with self.assertRaises(Exception):
            UserActivity.objects.create(
                user=self.user,
                date=self.today
            )


class SystemMetricsModelTest(TestCase):
    """Test cases for SystemMetrics model"""
    
    def setUp(self):
        self.today = date.today()
    
    def test_create_system_metrics(self):
        """Test creating system metrics record"""
        metrics = SystemMetrics.objects.create(
            date=self.today,
            total_users=1000,
            active_users=250,
            new_users=15,
            premium_users=50,
            total_conversations=500,
            total_messages=2500,
            total_files=150,
            total_storage_used=1073741824,  # 1GB
            avg_response_time=120.5,
            total_api_calls=5000,
            error_rate=2.5,
            uptime_percentage=99.9,
            total_revenue=1250.00,
            new_subscriptions=5,
            cancelled_subscriptions=2,
            custom_metrics={'feature_x_usage': 75}
        )
        
        self.assertEqual(metrics.date, self.today)
        self.assertEqual(metrics.total_users, 1000)
        self.assertEqual(metrics.active_users, 250)
        self.assertEqual(metrics.total_storage_used, 1073741824)
        self.assertEqual(metrics.error_rate, 2.5)
        self.assertEqual(metrics.custom_metrics['feature_x_usage'], 75)
    
    def test_system_metrics_str_representation(self):
        """Test string representation of system metrics"""
        metrics = SystemMetrics.objects.create(
            date=self.today,
            total_users=1000
        )
        
        expected_str = f"System Metrics - {self.today}"
        self.assertEqual(str(metrics), expected_str)
    
    def test_system_metrics_unique_constraint(self):
        """Test unique constraint on date"""
        SystemMetrics.objects.create(
            date=self.today,
            total_users=1000
        )
        
        # Creating another metrics for same date should raise error
        with self.assertRaises(Exception):
            SystemMetrics.objects.create(
                date=self.today,
                total_users=1500
            )


class ReportModelTest(TestCase):
    """Test cases for Report model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.today = date.today()
    
    def test_create_report(self):
        """Test creating a report"""
        report = Report.objects.create(
            name='User Activity Report',
            description='Monthly user activity analysis',
            report_type='user_activity',
            report_format='csv',
            start_date=self.today - timedelta(days=30),
            end_date=self.today,
            requested_by=self.user,
            filters={'active_only': True},
            parameters={'include_charts': True}
        )
        
        self.assertEqual(report.name, 'User Activity Report')
        self.assertEqual(report.report_type, 'user_activity')
        self.assertEqual(report.report_format, 'csv')
        self.assertEqual(report.requested_by, self.user)
        self.assertEqual(report.status, 'pending')
        self.assertEqual(report.progress, 0)
        self.assertEqual(report.filters['active_only'], True)
    
    def test_report_str_representation(self):
        """Test string representation of report"""
        report = Report.objects.create(
            name='Test Report',
            report_type='user_activity',
            requested_by=self.user
        )
        
        expected_str = "Test Report (user_activity)"
        self.assertEqual(str(report), expected_str)
    
    def test_mark_completed(self):
        """Test marking report as completed"""
        report = Report.objects.create(
            name='Test Report',
            report_type='user_activity',
            requested_by=self.user
        )
        
        test_data = {'users': 100, 'activities': 500}
        report.mark_completed(test_data, '/path/to/file.csv', 1024)
        
        self.assertEqual(report.status, 'completed')
        self.assertEqual(report.progress, 100)
        self.assertEqual(report.data, test_data)
        self.assertEqual(report.file_path, '/path/to/file.csv')
        self.assertEqual(report.file_size, 1024)
        self.assertIsNotNone(report.completed_at)
    
    def test_mark_failed(self):
        """Test marking report as failed"""
        report = Report.objects.create(
            name='Test Report',
            report_type='user_activity',
            requested_by=self.user
        )
        
        error_message = 'Database connection failed'
        report.mark_failed(error_message)
        
        self.assertEqual(report.status, 'failed')
        self.assertEqual(report.error_message, error_message)
        self.assertIsNotNone(report.completed_at)


class FeatureUsageModelTest(TestCase):
    """Test cases for FeatureUsage model"""
    
    def setUp(self):
        self.today = date.today()
    
    def test_create_feature_usage(self):
        """Test creating feature usage record"""
        usage = FeatureUsage.objects.create(
            feature_name='chat_interface',
            feature_category='communication',
            date=self.today,
            total_uses=150,
            unique_users=45,
            usage_data={
                'peak_hour': 14,
                'avg_session_length': 25.5,
                'popular_features': ['send_message', 'file_share']
            }
        )
        
        self.assertEqual(usage.feature_name, 'chat_interface')
        self.assertEqual(usage.feature_category, 'communication')
        self.assertEqual(usage.total_uses, 150)
        self.assertEqual(usage.unique_users, 45)
        self.assertEqual(usage.usage_data['peak_hour'], 14)
    
    def test_feature_usage_str_representation(self):
        """Test string representation of feature usage"""
        usage = FeatureUsage.objects.create(
            feature_name='chat_interface',
            date=self.today
        )
        
        expected_str = f"chat_interface - {self.today}"
        self.assertEqual(str(usage), expected_str)


class ErrorLogModelTest(TestCase):
    """Test cases for ErrorLog model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
    
    def test_create_error_log(self):
        """Test creating an error log"""
        error_log = ErrorLog.objects.create(
            level='error',
            message='Database connection timeout',
            exception_type='ConnectionError',
            stack_trace='Traceback (most recent call last):\n  File...',
            url='/api/users/',
            method='GET',
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0 Test Browser',
            context={
                'request_id': 'req-123',
                'user_id': self.user.id,
                'timestamp': '2023-01-01T12:00:00Z'
            }
        )
        
        self.assertEqual(error_log.level, 'error')
        self.assertEqual(error_log.message, 'Database connection timeout')
        self.assertEqual(error_log.exception_type, 'ConnectionError')
        self.assertEqual(error_log.user, self.user)
        self.assertFalse(error_log.is_resolved)
        self.assertEqual(error_log.context['request_id'], 'req-123')
    
    def test_error_log_str_representation(self):
        """Test string representation of error log"""
        error_log = ErrorLog.objects.create(
            level='error',
            message='Test error message',
            exception_type='TestError'
        )
        
        expected_str = "ERROR: Test error message"
        self.assertEqual(str(error_log), expected_str)
    
    def test_mark_resolved(self):
        """Test marking error as resolved"""
        error_log = ErrorLog.objects.create(
            level='error',
            message='Test error',
            exception_type='TestError'
        )
        
        resolution_notes = 'Fixed by updating database configuration'
        error_log.mark_resolved(self.admin_user, resolution_notes)
        
        self.assertTrue(error_log.is_resolved)
        self.assertEqual(error_log.resolved_by, self.admin_user)
        self.assertEqual(error_log.resolution_notes, resolution_notes)
        self.assertIsNotNone(error_log.resolved_at)
    
    def test_error_log_ordering(self):
        """Test error logs are ordered by creation time"""
        error1 = ErrorLog.objects.create(
            level='error',
            message='First error',
            exception_type='Error1'
        )
        error2 = ErrorLog.objects.create(
            level='error',
            message='Second error',
            exception_type='Error2'
        )
        
        errors = list(ErrorLog.objects.all())
        self.assertEqual(errors[0], error2)  # Most recent first
        self.assertEqual(errors[1], error1)