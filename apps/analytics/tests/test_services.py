from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import date, timedelta
from unittest.mock import patch, MagicMock

from apps.analytics.models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog, EventType
)
from apps.analytics.services import (
    AnalyticsService, ReportService, ErrorTrackingService
)
from apps.chat.models import Conversation, ChatMessage
from apps.files.models import File

User = get_user_model()


class AnalyticsServiceTest(TestCase):
    """Test cases for AnalyticsService"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.service = AnalyticsService()
        self.today = date.today()
    
    def test_track_event(self):
        """Test tracking an analytics event"""
        event = self.service.track_event(
            event_type=EventType.USER_LOGIN,
            event_name='user_login',
            user=self.user,
            properties={'login_method': 'email'},
            metadata={'source': 'web'}
        )
        
        self.assertIsInstance(event, AnalyticsEvent)
        self.assertEqual(event.event_type, EventType.USER_LOGIN)
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.properties['login_method'], 'email')
    
    def test_track_user_login(self):
        """Test tracking user login event"""
        event = self.service.track_user_login(
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0 Test'
        )
        
        self.assertEqual(event.event_type, EventType.USER_LOGIN)
        self.assertEqual(event.event_name, 'user_login')
        self.assertEqual(event.ip_address, '192.168.1.1')
    
    def test_track_chat_message(self):
        """Test tracking chat message event"""
        conversation = Conversation.objects.create(
            user=self.user,
            title='Test Conversation'
        )
        message = ChatMessage.objects.create(
            conversation=conversation,
            content='Test message',
            role='user'
        )
        
        event = self.service.track_chat_message(
            user=self.user,
            message=message,
            conversation=conversation
        )
        
        self.assertEqual(event.event_type, EventType.CHAT_MESSAGE)
        self.assertEqual(event.content_object, message)
        self.assertEqual(event.properties['conversation_id'], str(conversation.id))
    
    def test_track_file_upload(self):
        """Test tracking file upload event"""
        file_obj = File.objects.create(
            user=self.user,
            original_name='test.txt',
            file_name='test_123.txt',
            file_size=1024,
            mime_type='text/plain'
        )
        
        event = self.service.track_file_upload(
            user=self.user,
            file=file_obj
        )
        
        self.assertEqual(event.event_type, EventType.FILE_UPLOAD)
        self.assertEqual(event.content_object, file_obj)
        self.assertEqual(event.properties['file_size'], 1024)
        self.assertEqual(event.properties['mime_type'], 'text/plain')
    
    def test_update_user_activity(self):
        """Test updating user activity"""
        # Create initial activity
        activity = self.service.update_user_activity(
            user=self.user,
            date=self.today,
            login_count=1,
            chat_messages_sent=5
        )
        
        self.assertEqual(activity.login_count, 1)
        self.assertEqual(activity.chat_messages_sent, 5)
        
        # Update existing activity
        updated_activity = self.service.update_user_activity(
            user=self.user,
            date=self.today,
            login_count=1,  # Additional login
            chat_messages_sent=3  # Additional messages
        )
        
        self.assertEqual(updated_activity.login_count, 2)
        self.assertEqual(updated_activity.chat_messages_sent, 8)
    
    def test_get_user_activity(self):
        """Test getting user activity"""
        # Create some activity data
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2,
            chat_messages_sent=10
        )
        UserActivity.objects.create(
            user=self.user,
            date=self.today - timedelta(days=1),
            login_count=1,
            chat_messages_sent=5
        )
        
        # Get activity for date range
        activities = self.service.get_user_activity(
            user=self.user,
            start_date=self.today - timedelta(days=1),
            end_date=self.today
        )
        
        self.assertEqual(len(activities), 2)
        self.assertEqual(activities[0].date, self.today)  # Most recent first
    
    def test_get_system_stats(self):
        """Test getting system statistics"""
        # Create some test data
        User.objects.create_user('user2', 'user2@test.com', 'pass')
        User.objects.create_user('user3', 'user3@test.com', 'pass')
        
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=1
        )
        
        stats = self.service.get_system_stats(
            start_date=self.today,
            end_date=self.today
        )
        
        self.assertIn('total_users', stats)
        self.assertIn('active_users', stats)
        self.assertIn('total_events', stats)
        self.assertEqual(stats['total_users'], 3)
        self.assertEqual(stats['active_users'], 1)
    
    def test_get_dashboard_stats(self):
        """Test getting dashboard statistics"""
        # Create some test data
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2,
            chat_messages_sent=10
        )
        
        stats = self.service.get_dashboard_stats(
            start_date=self.today - timedelta(days=7),
            end_date=self.today
        )
        
        self.assertIn('user_stats', stats)
        self.assertIn('content_stats', stats)
        self.assertIn('performance_stats', stats)
        self.assertIn('revenue_stats', stats)
    
    def test_get_chart_data(self):
        """Test getting chart data"""
        # Create some test data
        for i in range(7):
            date_obj = self.today - timedelta(days=i)
            UserActivity.objects.create(
                user=self.user,
                date=date_obj,
                login_count=i + 1,
                chat_messages_sent=i * 2
            )
        
        chart_data = self.service.get_chart_data(
            chart_type='user_growth',
            start_date=self.today - timedelta(days=7),
            end_date=self.today
        )
        
        self.assertIn('labels', chart_data)
        self.assertIn('datasets', chart_data)
        self.assertEqual(len(chart_data['labels']), 8)  # 7 days + today


class ReportServiceTest(TestCase):
    """Test cases for ReportService"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.service = ReportService()
        self.today = date.today()
    
    def test_create_report(self):
        """Test creating a report"""
        report = self.service.create_report(
            name='Test Report',
            report_type='user_activity',
            report_format='json',
            start_date=self.today - timedelta(days=7),
            end_date=self.today,
            requested_by=self.user,
            filters={'active_only': True}
        )
        
        self.assertIsInstance(report, Report)
        self.assertEqual(report.name, 'Test Report')
        self.assertEqual(report.report_type, 'user_activity')
        self.assertEqual(report.status, 'pending')
    
    @patch('apps.analytics.services.ReportService._save_report_file')
    def test_generate_report_data(self, mock_save_file):
        """Test generating report data"""
        mock_save_file.return_value = ('/path/to/file.json', 1024)
        
        # Create test data
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2,
            chat_messages_sent=10
        )
        
        report = Report.objects.create(
            name='Test Report',
            report_type='user_activity',
            report_format='json',
            start_date=self.today,
            end_date=self.today,
            requested_by=self.user
        )
        
        result = self.service.generate_report_data(report)
        
        self.assertTrue(result)
        self.assertEqual(report.status, 'completed')
        self.assertIsNotNone(report.data)
    
    def test_generate_user_activity_data(self):
        """Test generating user activity report data"""
        # Create test data
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2,
            chat_messages_sent=10
        )
        
        data = self.service._generate_user_activity_data(
            start_date=self.today,
            end_date=self.today
        )
        
        self.assertIn('summary', data)
        self.assertIn('activities', data)
        self.assertEqual(len(data['activities']), 1)
    
    def test_generate_system_metrics_data(self):
        """Test generating system metrics report data"""
        # Create test data
        SystemMetrics.objects.create(
            date=self.today,
            total_users=100,
            active_users=25
        )
        
        data = self.service._generate_system_metrics_data(
            start_date=self.today,
            end_date=self.today
        )
        
        self.assertIn('summary', data)
        self.assertIn('metrics', data)
        self.assertEqual(len(data['metrics']), 1)
    
    def test_generate_feature_usage_data(self):
        """Test generating feature usage report data"""
        # Create test data
        FeatureUsage.objects.create(
            feature_name='chat',
            date=self.today,
            total_uses=50,
            unique_users=10
        )
        
        data = self.service._generate_feature_usage_data(
            start_date=self.today,
            end_date=self.today
        )
        
        self.assertIn('summary', data)
        self.assertIn('features', data)
        self.assertEqual(len(data['features']), 1)
    
    def test_generate_error_logs_data(self):
        """Test generating error logs report data"""
        # Create test data
        ErrorLog.objects.create(
            level='error',
            message='Test error',
            exception_type='TestError',
            user=self.user
        )
        
        data = self.service._generate_error_logs_data(
            start_date=self.today,
            end_date=self.today
        )
        
        self.assertIn('summary', data)
        self.assertIn('errors', data)
        self.assertEqual(len(data['errors']), 1)


class ErrorTrackingServiceTest(TestCase):
    """Test cases for ErrorTrackingService"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.service = ErrorTrackingService()
    
    @patch('apps.analytics.services.AnalyticsService.track_event')
    def test_log_error(self, mock_track_event):
        """Test logging an error"""
        mock_track_event.return_value = MagicMock()
        
        error_log = self.service.log_error(
            level='error',
            message='Test error message',
            exception_type='TestError',
            stack_trace='Test stack trace',
            url='/test/url/',
            method='GET',
            user=self.user,
            ip_address='192.168.1.1',
            context={'test': 'data'}
        )
        
        self.assertIsInstance(error_log, ErrorLog)
        self.assertEqual(error_log.level, 'error')
        self.assertEqual(error_log.message, 'Test error message')
        self.assertEqual(error_log.user, self.user)
        
        # Verify analytics event was tracked
        mock_track_event.assert_called_once()
    
    def test_get_error_stats(self):
        """Test getting error statistics"""
        # Create test data
        ErrorLog.objects.create(
            level='error',
            message='Error 1',
            exception_type='Error1'
        )
        ErrorLog.objects.create(
            level='warning',
            message='Warning 1',
            exception_type='Warning1'
        )
        ErrorLog.objects.create(
            level='error',
            message='Error 2',
            exception_type='Error2',
            is_resolved=True
        )
        
        stats = self.service.get_error_stats(
            start_date=date.today(),
            end_date=date.today()
        )
        
        self.assertIn('total_errors', stats)
        self.assertIn('by_level', stats)
        self.assertIn('by_type', stats)
        self.assertIn('resolution_rate', stats)
        
        self.assertEqual(stats['total_errors'], 3)
        self.assertEqual(stats['by_level']['error'], 2)
        self.assertEqual(stats['by_level']['warning'], 1)
        self.assertEqual(stats['resolution_rate'], 33.33)  # 1 out of 3 resolved
    
    def test_get_top_errors(self):
        """Test getting top errors by frequency"""
        # Create test data
        for i in range(3):
            ErrorLog.objects.create(
                level='error',
                message='Common error',
                exception_type='CommonError'
            )
        
        for i in range(2):
            ErrorLog.objects.create(
                level='error',
                message='Less common error',
                exception_type='LessCommonError'
            )
        
        ErrorLog.objects.create(
            level='error',
            message='Rare error',
            exception_type='RareError'
        )
        
        top_errors = self.service.get_top_errors(
            start_date=date.today(),
            end_date=date.today(),
            limit=2
        )
        
        self.assertEqual(len(top_errors), 2)
        self.assertEqual(top_errors[0]['exception_type'], 'CommonError')
        self.assertEqual(top_errors[0]['count'], 3)
        self.assertEqual(top_errors[1]['exception_type'], 'LessCommonError')
        self.assertEqual(top_errors[1]['count'], 2)