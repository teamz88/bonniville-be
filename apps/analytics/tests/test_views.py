from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from datetime import date, timedelta
import json

from apps.analytics.models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog, EventType
)

User = get_user_model()


class AnalyticsEventViewTest(APITestCase):
    """Test cases for AnalyticsEvent API views"""
    
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
            is_staff=True,
            is_superuser=True
        )
        self.client.force_authenticate(user=self.user)
    
    def test_list_analytics_events(self):
        """Test listing analytics events"""
        # Create test events
        AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='user_login',
            user=self.user
        )
        AnalyticsEvent.objects.create(
            event_type=EventType.CHAT_MESSAGE,
            event_name='message_sent',
            user=self.user
        )
        
        url = reverse('analytics:events-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
    
    def test_create_analytics_event(self):
        """Test creating an analytics event"""
        url = reverse('analytics:events-list')
        data = {
            'event_type': EventType.USER_LOGIN,
            'event_name': 'user_login',
            'event_description': 'User logged in',
            'properties': {'login_method': 'email'},
            'metadata': {'source': 'web'}
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AnalyticsEvent.objects.count(), 1)
        
        event = AnalyticsEvent.objects.first()
        self.assertEqual(event.event_type, EventType.USER_LOGIN)
        self.assertEqual(event.user, self.user)
    
    def test_filter_events_by_type(self):
        """Test filtering events by type"""
        AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login',
            user=self.user
        )
        AnalyticsEvent.objects.create(
            event_type=EventType.CHAT_MESSAGE,
            event_name='message',
            user=self.user
        )
        
        url = reverse('analytics:events-list')
        response = self.client.get(url, {'event_type': EventType.USER_LOGIN})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(
            response.data['results'][0]['event_type'],
            EventType.USER_LOGIN
        )
    
    def test_user_can_only_see_own_events(self):
        """Test that users can only see their own events"""
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        # Create events for both users
        AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login',
            user=self.user
        )
        AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login',
            user=other_user
        )
        
        url = reverse('analytics:events-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['user']['id'], self.user.id)
    
    def test_admin_can_see_all_events(self):
        """Test that admin users can see all events"""
        self.client.force_authenticate(user=self.admin_user)
        
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        # Create events for both users
        AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login',
            user=self.user
        )
        AnalyticsEvent.objects.create(
            event_type=EventType.USER_LOGIN,
            event_name='login',
            user=other_user
        )
        
        url = reverse('analytics:events-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)


class UserActivityViewTest(APITestCase):
    """Test cases for UserActivity API views"""
    
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
        self.today = date.today()
    
    def test_list_user_activity_as_user(self):
        """Test listing user activity as regular user"""
        self.client.force_authenticate(user=self.user)
        
        # Create activity for user
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2,
            chat_messages_sent=10
        )
        
        url = reverse('analytics:user-activity-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_list_user_activity_as_admin(self):
        """Test listing user activity as admin"""
        self.client.force_authenticate(user=self.admin_user)
        
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        # Create activity for both users
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2
        )
        UserActivity.objects.create(
            user=other_user,
            date=self.today,
            login_count=1
        )
        
        url = reverse('analytics:user-activity-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
    
    def test_filter_user_activity_by_user(self):
        """Test filtering user activity by user (admin only)"""
        self.client.force_authenticate(user=self.admin_user)
        
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2
        )
        UserActivity.objects.create(
            user=other_user,
            date=self.today,
            login_count=1
        )
        
        url = reverse('analytics:user-activity-list')
        response = self.client.get(url, {'user': self.user.id})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['user']['id'], self.user.id)


class SystemMetricsViewTest(APITestCase):
    """Test cases for SystemMetrics API views"""
    
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.regular_user = User.objects.create_user(
            username='user',
            email='user@example.com',
            password='userpass123'
        )
        self.today = date.today()
    
    def test_list_system_metrics_as_admin(self):
        """Test listing system metrics as admin"""
        self.client.force_authenticate(user=self.admin_user)
        
        SystemMetrics.objects.create(
            date=self.today,
            total_users=100,
            active_users=25
        )
        
        url = reverse('analytics:system-metrics-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_list_system_metrics_as_regular_user(self):
        """Test that regular users cannot access system metrics"""
        self.client.force_authenticate(user=self.regular_user)
        
        url = reverse('analytics:system-metrics-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class ReportViewTest(APITestCase):
    """Test cases for Report API views"""
    
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
        self.today = date.today()
    
    def test_create_report(self):
        """Test creating a report"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('analytics:reports-list')
        data = {
            'name': 'Test Report',
            'description': 'Test report description',
            'report_type': 'user_activity',
            'report_format': 'json',
            'start_date': str(self.today - timedelta(days=7)),
            'end_date': str(self.today),
            'filters': {'active_only': True}
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Report.objects.count(), 1)
        
        report = Report.objects.first()
        self.assertEqual(report.name, 'Test Report')
        self.assertEqual(report.requested_by, self.user)
    
    def test_list_user_reports(self):
        """Test listing user's own reports"""
        self.client.force_authenticate(user=self.user)
        
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        # Create reports for both users
        Report.objects.create(
            name='User Report',
            report_type='user_activity',
            requested_by=self.user
        )
        Report.objects.create(
            name='Other Report',
            report_type='user_activity',
            requested_by=other_user
        )
        
        url = reverse('analytics:reports-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'User Report')
    
    def test_get_report_detail(self):
        """Test getting report details"""
        self.client.force_authenticate(user=self.user)
        
        report = Report.objects.create(
            name='Test Report',
            report_type='user_activity',
            requested_by=self.user,
            status='completed',
            data={'test': 'data'}
        )
        
        url = reverse('analytics:reports-detail', args=[report.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Test Report')
        self.assertEqual(response.data['data'], {'test': 'data'})
    
    def test_cannot_access_other_user_report(self):
        """Test that users cannot access other users' reports"""
        self.client.force_authenticate(user=self.user)
        
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        report = Report.objects.create(
            name='Other Report',
            report_type='user_activity',
            requested_by=other_user
        )
        
        url = reverse('analytics:reports-detail', args=[report.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class ErrorLogViewTest(APITestCase):
    """Test cases for ErrorLog API views"""
    
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )
        self.regular_user = User.objects.create_user(
            username='user',
            email='user@example.com',
            password='userpass123'
        )
    
    def test_list_error_logs_as_admin(self):
        """Test listing error logs as admin"""
        self.client.force_authenticate(user=self.admin_user)
        
        ErrorLog.objects.create(
            level='error',
            message='Test error',
            exception_type='TestError'
        )
        
        url = reverse('analytics:error-logs-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_list_error_logs_as_regular_user(self):
        """Test that regular users cannot access error logs"""
        self.client.force_authenticate(user=self.regular_user)
        
        url = reverse('analytics:error-logs-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_update_error_log(self):
        """Test updating error log (marking as resolved)"""
        self.client.force_authenticate(user=self.admin_user)
        
        error_log = ErrorLog.objects.create(
            level='error',
            message='Test error',
            exception_type='TestError'
        )
        
        url = reverse('analytics:error-logs-detail', args=[error_log.id])
        data = {
            'is_resolved': True,
            'resolution_notes': 'Fixed the issue'
        }
        
        response = self.client.patch(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        error_log.refresh_from_db()
        self.assertTrue(error_log.is_resolved)
        self.assertEqual(error_log.resolution_notes, 'Fixed the issue')
        self.assertEqual(error_log.resolved_by, self.admin_user)
        self.assertIsNotNone(error_log.resolved_at)


class DashboardStatsViewTest(APITestCase):
    """Test cases for dashboard stats view"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.today = date.today()
    
    def test_get_dashboard_stats(self):
        """Test getting dashboard statistics"""
        self.client.force_authenticate(user=self.user)
        
        # Create some test data
        UserActivity.objects.create(
            user=self.user,
            date=self.today,
            login_count=2,
            chat_messages_sent=10
        )
        
        url = reverse('analytics:dashboard-stats')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user_stats', response.data)
        self.assertIn('content_stats', response.data)
        self.assertIn('performance_stats', response.data)
    
    def test_dashboard_stats_with_date_range(self):
        """Test dashboard stats with custom date range"""
        self.client.force_authenticate(user=self.user)
        
        start_date = self.today - timedelta(days=7)
        end_date = self.today
        
        url = reverse('analytics:dashboard-stats')
        response = self.client.get(url, {
            'start_date': str(start_date),
            'end_date': str(end_date)
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user_stats', response.data)


class TrackEventViewTest(APITestCase):
    """Test cases for track event view"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_track_custom_event(self):
        """Test tracking a custom event"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('analytics:track-event')
        data = {
            'event_type': EventType.API_CALL,
            'event_name': 'custom_action',
            'event_description': 'User performed custom action',
            'properties': {'action_type': 'button_click'},
            'metadata': {'page': 'dashboard'}
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(AnalyticsEvent.objects.count(), 1)
        
        event = AnalyticsEvent.objects.first()
        self.assertEqual(event.event_name, 'custom_action')
        self.assertEqual(event.user, self.user)
        self.assertIsNotNone(event.ip_address)  # Should be captured from request
    
    def test_track_event_captures_request_metadata(self):
        """Test that tracking captures request metadata"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('analytics:track-event')
        data = {
            'event_type': EventType.API_CALL,
            'event_name': 'test_event'
        }
        
        # Add custom headers
        response = self.client.post(
            url, 
            data, 
            format='json',
            HTTP_USER_AGENT='Test User Agent',
            HTTP_REFERER='https://example.com/page'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        event = AnalyticsEvent.objects.first()
        self.assertEqual(event.user_agent, 'Test User Agent')
        self.assertEqual(event.referer, 'https://example.com/page')