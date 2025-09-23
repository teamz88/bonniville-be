from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Count, Sum, Avg, Q, F
from datetime import datetime, timedelta, date
from typing import Dict, List, Any, Optional
import json
import csv
import io
from decimal import Decimal

from .models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog, EventType, PaymentRecord
)
from ..chat.models import ChatMessage

User = get_user_model()


class AnalyticsService:
    """Service for handling analytics operations"""
    
    @staticmethod
    def track_event(
        event_type: str,
        event_name: str,
        user=None,
        session_id: str = None,
        ip_address: str = None,
        user_agent: str = None,
        referer: str = None,
        properties: Dict = None,
        metadata: Dict = None,
        event_description: str = None,
        related_object=None
    ) -> AnalyticsEvent:
        """Track an analytics event"""
        event = AnalyticsEvent.objects.create(
            event_type=event_type,
            event_name=event_name,
            event_description=event_description or '',
            user=user,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            referer=referer,
            properties=properties or {},
            metadata=metadata or {},
            content_object=related_object
        )
        
        # Update user activity if user is provided
        if user and event_type in [
            EventType.USER_LOGIN, EventType.CHAT_MESSAGE, 
            EventType.FILE_UPLOAD, EventType.FILE_DOWNLOAD
        ]:
            AnalyticsService._update_user_activity(user, event_type)
        
        return event
    
    @staticmethod
    def _update_user_activity(user, event_type: str):
        """Update user activity metrics"""
        today = timezone.now().date()
        activity, created = UserActivity.objects.get_or_create(
            user=user,
            date=today,
            defaults={
                'login_count': 0,
                'chat_messages_sent': 0,
                'files_uploaded': 0,
                'files_downloaded': 0,
                'pages_visited': 0,
                'api_calls_made': 0,
                'total_session_time': 0,
                'active_time': 0,
                'features_used': []
            }
        )
        
        # Update specific metrics based on event type
        if event_type == EventType.USER_LOGIN:
            activity.login_count = F('login_count') + 1
        elif event_type == EventType.CHAT_MESSAGE:
            activity.chat_messages_sent = F('chat_messages_sent') + 1
        elif event_type == EventType.FILE_UPLOAD:
            activity.files_uploaded = F('files_uploaded') + 1
        elif event_type == EventType.FILE_DOWNLOAD:
            activity.files_downloaded = F('files_downloaded') + 1
        
        activity.save(update_fields=[
            'login_count', 'chat_messages_sent', 'files_uploaded', 
            'files_downloaded', 'updated_at'
        ])
    
    @staticmethod
    def get_user_activity_stats(
        user_id: int = None,
        start_date: date = None,
        end_date: date = None
    ) -> Dict[str, Any]:
        """Get user activity statistics"""
        queryset = UserActivity.objects.all()
        
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        if start_date:
            queryset = queryset.filter(date__gte=start_date)
        
        if end_date:
            queryset = queryset.filter(date__lte=end_date)
        
        stats = queryset.aggregate(
            total_logins=Sum('login_count'),
            total_messages=Sum('chat_messages_sent'),
            total_uploads=Sum('files_uploaded'),
            total_downloads=Sum('files_downloaded'),
            total_pages=Sum('pages_visited'),
            total_api_calls=Sum('api_calls_made'),
            total_session_time=Sum('total_session_time'),
            total_active_time=Sum('active_time'),
            avg_session_time=Avg('total_session_time'),
            avg_active_time=Avg('active_time')
        )
        
        # Convert None values to 0
        for key, value in stats.items():
            if value is None:
                stats[key] = 0
        
        return stats
    
    @staticmethod
    def get_subscription_stats(
        start_date: date = None,
        end_date: date = None
    ) -> Dict[str, Any]:
        """Get subscription statistics"""
        from apps.authentication.models import User
        
        queryset = User.objects.all()
        
        if start_date:
            queryset = queryset.filter(date_joined__date__gte=start_date)
        
        if end_date:
            queryset = queryset.filter(date_joined__date__lte=end_date)
        
        stats = {
            'total_users': User.objects.count(),
            'active_subscriptions': User.objects.filter(
                subscription_status=User.SubscriptionStatus.ACTIVE
            ).count(),
            'expired_subscriptions': User.objects.filter(
                subscription_status=User.SubscriptionStatus.EXPIRED
            ).count(),
            'cancelled_subscriptions': User.objects.filter(
                subscription_status=User.SubscriptionStatus.CANCELLED
            ).count(),
            'subscription_types': dict(
                User.objects.values('subscription_type').annotate(
                    count=Count('id')
                ).values_list('subscription_type', 'count')
            ),
            'lifetime_subscriptions': User.objects.filter(
                subscription_type=User.SubscriptionType.LIFETIME
            ).count(),
            'monthly_subscriptions': User.objects.filter(
                subscription_type__in=[User.SubscriptionType.BASIC, User.SubscriptionType.PREMIUM]
            ).count()
        }
        
        return stats
    
    @staticmethod
    def get_payment_stats(
        start_date: date = None,
        end_date: date = None
    ) -> Dict[str, Any]:
        """Get payment statistics"""
        queryset = PaymentRecord.objects.all()
        
        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)
        
        completed_payments = queryset.filter(status='completed')
        
        stats = {
            'total_payments': queryset.count(),
            'completed_payments': completed_payments.count(),
            'failed_payments': queryset.filter(status='failed').count(),
            'pending_payments': queryset.filter(status='pending').count(),
            'total_revenue': completed_payments.aggregate(
                total=Sum('amount')
            )['total'] or Decimal('0.00'),
            'monthly_revenue': completed_payments.filter(
                payment_type__in=['subscription', 'renewal']
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'lifetime_revenue': completed_payments.filter(
                payment_type='lifetime'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'payment_methods': dict(
                completed_payments.values('gateway').annotate(
                    count=Count('id')
                ).values_list('gateway', 'count')
            ),
            'recent_payments': list(
                completed_payments.order_by('-created_at')[:10].values(
                    'id', 'user__username', 'amount', 'currency',
                    'payment_type', 'created_at'
                )
            )
        }
        
        return stats
    
    @staticmethod
    def get_user_dashboard_stats(
        user_id: int = None,
        start_date: date = None,
        end_date: date = None
    ) -> Dict[str, Any]:
        """Get user-specific dashboard statistics"""
        from apps.authentication.models import User
        from apps.files.models import File
        from apps.chat.models import Conversation, ChatMessage
        
        if user_id:
            user = User.objects.get(id=user_id)
            
            # User's subscription info
            subscription_info = {
                'subscription_type': user.subscription_type,
                'subscription_status': user.subscription_status,
                'subscription_start_date': user.subscription_start_date,
                'subscription_end_date': user.subscription_end_date,
                'days_until_expiry': user.days_until_expiry,
                'is_active': user.is_subscription_active
            }
            
            # User's payment history
            payment_history = list(
                PaymentRecord.objects.filter(user=user).order_by('-created_at')[:10].values(
                    'amount', 'currency', 'payment_type', 'status', 'created_at'
                )
            )
            
            # User's file statistics
            user_files = File.objects.filter(user=user)
            file_stats = {
                'total_files': user_files.count(),
                'total_storage_used': user_files.aggregate(
                    total=Sum('file_size')
                )['total'] or 0,
                'files_by_category': dict(
                    user_files.values('category').annotate(
                        count=Count('id')
                    ).values_list('category', 'count')
                )
            }
            
            # User's chat statistics
            user_conversations = Conversation.objects.filter(user=user)
            chat_stats = {
                'total_conversations': user_conversations.count(),
                'total_messages': ChatMessage.objects.filter(
                    conversation__user=user
                ).count()
            }
            
            # User's activity statistics
            activity_queryset = UserActivity.objects.filter(user=user)
            if start_date:
                activity_queryset = activity_queryset.filter(date__gte=start_date)
            if end_date:
                activity_queryset = activity_queryset.filter(date__lte=end_date)
            
            activity_stats = {
                'total_logins': activity_queryset.aggregate(
                    total=Sum('login_count')
                )['total'] or 0,
                'total_session_time': activity_queryset.aggregate(
                    total=Sum('total_session_time')
                )['total'] or 0,
                'avg_session_time': activity_queryset.aggregate(
                    avg=Avg('total_session_time')
                )['avg'] or 0,
                'last_activity': user.last_activity
            }
            
            return {
                'user_info': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'date_joined': user.date_joined
                },
                'subscription_info': subscription_info,
                'payment_history': payment_history,
                'file_stats': file_stats,
                'chat_stats': chat_stats,
                'activity_stats': activity_stats
            }
        
        return {}
    
    @staticmethod
    def get_system_metrics(date_filter: date = None) -> SystemMetrics:
        """Get or create system metrics for a specific date"""
        target_date = date_filter or timezone.now().date()
        
        metrics, created = SystemMetrics.objects.get_or_create(
            date=target_date,
            defaults={
                'total_users': 0,
                'active_users': 0,
                'new_users': 0,
                'premium_users': 0,
                'total_conversations': 0,
                'total_messages': 0,
                'total_files': 0,
                'total_storage_used': 0,
                'avg_response_time': 0.0,
                'total_api_calls': 0,
                'error_rate': 0.0,
                'total_revenue': Decimal('0.00'),
                'new_subscriptions': 0,
                'cancelled_subscriptions': 0,
                'uptime_percentage': 100.0,
                'custom_metrics': {}
            }
        )
        
        if created:
            # Calculate metrics for the new record
            AnalyticsService._calculate_system_metrics(metrics, target_date)
        
        return metrics
    
    @staticmethod
    def _calculate_system_metrics(metrics: SystemMetrics, target_date: date):
        """Calculate system metrics for a specific date"""
        from apps.authentication.models import User
        from apps.chat.models import Conversation, ChatMessage
        from apps.files.models import File
        
        # User metrics
        metrics.total_users = User.objects.count()
        metrics.active_users = UserActivity.objects.filter(
            date=target_date
        ).count()
        metrics.new_users = User.objects.filter(
            date_joined__date=target_date
        ).count()
        metrics.premium_users = User.objects.filter(
            subscription_status='active'
        ).count()
        
        # Content metrics
        metrics.total_conversations = Conversation.objects.count()
        metrics.total_messages = ChatMessage.objects.count()
        metrics.total_files = File.objects.filter(deleted_at__isnull=True).count()
        metrics.total_storage_used = File.objects.filter(
            deleted_at__isnull=True
        ).aggregate(
            total=Sum('file_size')
        )['total'] or 0
        
        # API metrics
        api_events = AnalyticsEvent.objects.filter(
            event_type=EventType.API_CALL,
            created_at__date=target_date
        )
        metrics.total_api_calls = api_events.count()
        
        # Error rate
        error_events = AnalyticsEvent.objects.filter(
            event_type=EventType.ERROR_OCCURRED,
            created_at__date=target_date
        ).count()
        
        total_events = AnalyticsEvent.objects.filter(
            created_at__date=target_date
        ).count()
        
        if total_events > 0:
            metrics.error_rate = (error_events / total_events) * 100
        
        metrics.save()
    
    @staticmethod
    def get_dashboard_stats(
        start_date: date = None,
        end_date: date = None
    ) -> Dict[str, Any]:
        """Get dashboard statistics"""
        if not start_date:
            start_date = timezone.now().date() - timedelta(days=30)
        if not end_date:
            end_date = timezone.now().date()
        
        from apps.authentication.models import User
        from apps.chat.models import Conversation, ChatMessage
        from apps.files.models import File
        
        # Current stats
        today = timezone.now().date()
        
        # Token usage stats
        from .models import TokenUsage
        token_stats = TokenUsage.objects.filter(
            date__gte=start_date,
            date__lte=end_date
        ).aggregate(
            total_tokens=Sum('total_tokens'),
            total_input_tokens=Sum('input_tokens'),
            total_output_tokens=Sum('output_tokens'),
            total_messages=Sum('message_count')
        )
        
        stats = {
            # User stats
            'total_users': User.objects.count(),
            'active_users_today': UserActivity.objects.filter(
                date=today
            ).count(),
            'new_users_today': User.objects.filter(
                date_joined__date=today
            ).count(),
            'premium_users': User.objects.filter(
                subscription_status='active'
            ).count(),
            
            # Content stats
            'total_conversations': Conversation.objects.count(),
            'total_messages': ChatMessage.objects.count(),
            'total_files': File.objects.filter(deleted_at__isnull=True).count(),
            'total_storage_used': File.objects.filter(
                deleted_at__isnull=True
            ).aggregate(
                total=Sum('file_size')
            )['total'] or 0,
            
            # Token usage stats
            'total_tokens_used': token_stats['total_tokens'] or 0,
            'total_input_tokens': token_stats['total_input_tokens'] or 0,
            'total_output_tokens': token_stats['total_output_tokens'] or 0,
            'token_messages_count': token_stats['total_messages'] or 0,
            
            # Performance stats (from latest system metrics)
            'avg_response_time': 0.0,
            'error_rate': 0.0,
            'uptime_percentage': 100.0,
            
            # Revenue stats
            'total_revenue': Decimal('0.00'),
            'monthly_revenue': Decimal('0.00'),
        }
        
        # Get latest system metrics for performance stats
        latest_metrics = SystemMetrics.objects.filter(
            date__lte=today
        ).order_by('-date').first()
        
        if latest_metrics:
            stats.update({
                'avg_response_time': latest_metrics.avg_response_time,
                'error_rate': latest_metrics.error_rate,
                'uptime_percentage': latest_metrics.uptime_percentage,
                'total_revenue': latest_metrics.total_revenue,
            })
        
        # Monthly revenue (current month)
        current_month_start = today.replace(day=1)
        monthly_metrics = SystemMetrics.objects.filter(
            date__gte=current_month_start,
            date__lte=today
        ).aggregate(
            total=Sum('total_revenue')
        )
        stats['monthly_revenue'] = monthly_metrics['total'] or Decimal('0.00')
        
        # Chart data
        stats.update({
            'user_growth_chart': AnalyticsService._get_user_growth_chart(
                start_date, end_date
            ),
            'revenue_chart': AnalyticsService._get_revenue_chart(
                start_date, end_date
            ),
            'activity_chart': AnalyticsService._get_activity_chart(
                start_date, end_date
            ),
            'feature_usage_chart': AnalyticsService._get_feature_usage_chart(
                start_date, end_date
            ),
        })
        
        return stats
    
    @staticmethod
    def _get_user_growth_chart(
        start_date: date, 
        end_date: date
    ) -> List[Dict[str, Any]]:
        """Get user growth chart data"""
        from apps.authentication.models import User
        
        chart_data = []
        current_date = start_date
        
        while current_date <= end_date:
            new_users = User.objects.filter(
                date_joined__date=current_date
            ).count()
            
            total_users = User.objects.filter(
                date_joined__date__lte=current_date
            ).count()
            
            chart_data.append({
                'date': current_date.isoformat(),
                'new_users': new_users,
                'total_users': total_users
            })
            
            current_date += timedelta(days=1)
        
        return chart_data
    
    @staticmethod
    def _get_revenue_chart(
        start_date: date, 
        end_date: date
    ) -> List[Dict[str, Any]]:
        """Get revenue chart data"""
        chart_data = []
        current_date = start_date
        
        while current_date <= end_date:
            metrics = SystemMetrics.objects.filter(
                date=current_date
            ).first()
            
            revenue = metrics.total_revenue if metrics else Decimal('0.00')
            
            chart_data.append({
                'date': current_date.isoformat(),
                'revenue': float(revenue)
            })
            
            current_date += timedelta(days=1)
        
        return chart_data
    
    @staticmethod
    def _get_activity_chart(
        start_date: date, 
        end_date: date
    ) -> List[Dict[str, Any]]:
        """Get activity chart data"""
        chart_data = []
        current_date = start_date
        
        while current_date <= end_date:
            # Get questions asked (assistant messages) from ChatMessage table
            questions_count = ChatMessage.objects.filter(
                created_at__date=current_date,
                message_type=ChatMessage.MessageType.ASSISTANT
            ).count()
            
            # Get other activity stats from UserActivity table
            activity_stats = UserActivity.objects.filter(
                date=current_date
            ).aggregate(
                total_uploads=Sum('files_uploaded'),
                active_users=Count('user', distinct=True)
            )
            
            chart_data.append({
                'date': current_date.isoformat(),
                'questions': questions_count,
                'uploads': activity_stats['total_uploads'] or 0,
                'active_users': activity_stats['active_users'] or 0
            })
            
            current_date += timedelta(days=1)
        
        return chart_data
    
    @staticmethod
    def _get_feature_usage_chart(
        start_date: date, 
        end_date: date
    ) -> List[Dict[str, Any]]:
        """Get feature usage chart data"""
        features = FeatureUsage.objects.filter(
            date__gte=start_date,
            date__lte=end_date
        ).values('feature_name').annotate(
            total_uses=Sum('total_uses'),
            unique_users=Sum('unique_users')
        ).order_by('-total_uses')[:10]
        
        return list(features)


class ReportService:
    """Service for handling report generation"""
    
    @staticmethod
    def create_report(
        name: str,
        report_type: str,
        report_format: str,
        start_date: date,
        end_date: date,
        user,
        description: str = None,
        filters: Dict = None,
        parameters: Dict = None
    ) -> Report:
        """Create a new report"""
        report = Report.objects.create(
            name=name,
            description=description or '',
            report_type=report_type,
            report_format=report_format,
            start_date=start_date,
            end_date=end_date,
            filters=filters or {},
            parameters=parameters or {},
            requested_by=user
        )
        
        # Generate report asynchronously (in a real app, use Celery)
        ReportService._generate_report(report)
        
        return report
    
    @staticmethod
    def _generate_report(report: Report):
        """Generate report data"""
        try:
            report.status = 'processing'
            report.progress = 0
            report.save()
            
            # Generate data based on report type
            if report.report_type == 'user_activity':
                data = ReportService._generate_user_activity_report(report)
            elif report.report_type == 'system_metrics':
                data = ReportService._generate_system_metrics_report(report)
            elif report.report_type == 'feature_usage':
                data = ReportService._generate_feature_usage_report(report)
            elif report.report_type == 'error_logs':
                data = ReportService._generate_error_logs_report(report)
            else:
                raise ValueError(f"Unknown report type: {report.report_type}")
            
            report.progress = 50
            report.save()
            
            # Save data and generate file
            report.data = data
            
            if report.report_format == 'json':
                file_content = json.dumps(data, indent=2, default=str)
                file_extension = 'json'
            elif report.report_format == 'csv':
                file_content = ReportService._convert_to_csv(data)
                file_extension = 'csv'
            else:
                raise ValueError(f"Unknown report format: {report.report_format}")
            
            # Save file (in a real app, save to storage service)
            file_path = f"reports/{report.id}_{report.name}.{file_extension}"
            report.file_path = file_path
            report.file_size = len(file_content.encode('utf-8'))
            
            report.progress = 100
            report.mark_completed()
            
        except Exception as e:
            report.mark_failed(str(e))
    
    @staticmethod
    def _generate_user_activity_report(report: Report) -> Dict[str, Any]:
        """Generate user activity report"""
        activities = UserActivity.objects.filter(
            date__gte=report.start_date,
            date__lte=report.end_date
        )
        
        # Apply filters
        filters = report.filters
        if filters.get('user_id'):
            activities = activities.filter(user_id=filters['user_id'])
        
        data = {
            'report_info': {
                'name': report.name,
                'type': report.report_type,
                'start_date': report.start_date.isoformat(),
                'end_date': report.end_date.isoformat(),
                'generated_at': timezone.now().isoformat()
            },
            'summary': activities.aggregate(
                total_users=Count('user', distinct=True),
                total_logins=Sum('login_count'),
                total_messages=Sum('chat_messages_sent'),
                total_uploads=Sum('files_uploaded'),
                total_downloads=Sum('files_downloaded'),
                avg_session_time=Avg('total_session_time')
            ),
            'daily_breakdown': list(
                activities.values('date').annotate(
                    users=Count('user', distinct=True),
                    logins=Sum('login_count'),
                    messages=Sum('chat_messages_sent'),
                    uploads=Sum('files_uploaded'),
                    downloads=Sum('files_downloaded')
                ).order_by('date')
            ),
            'user_breakdown': list(
                activities.values(
                    'user__username', 'user__email'
                ).annotate(
                    total_logins=Sum('login_count'),
                    total_messages=Sum('chat_messages_sent'),
                    total_uploads=Sum('files_uploaded'),
                    total_downloads=Sum('files_downloaded'),
                    avg_session_time=Avg('total_session_time')
                ).order_by('-total_messages')
            )
        }
        
        return data
    
    @staticmethod
    def _generate_system_metrics_report(report: Report) -> Dict[str, Any]:
        """Generate system metrics report"""
        metrics = SystemMetrics.objects.filter(
            date__gte=report.start_date,
            date__lte=report.end_date
        ).order_by('date')
        
        data = {
            'report_info': {
                'name': report.name,
                'type': report.report_type,
                'start_date': report.start_date.isoformat(),
                'end_date': report.end_date.isoformat(),
                'generated_at': timezone.now().isoformat()
            },
            'summary': metrics.aggregate(
                avg_users=Avg('total_users'),
                avg_active_users=Avg('active_users'),
                total_new_users=Sum('new_users'),
                avg_response_time=Avg('avg_response_time'),
                avg_error_rate=Avg('error_rate'),
                total_revenue=Sum('total_revenue')
            ),
            'daily_metrics': list(
                metrics.values(
                    'date', 'total_users', 'active_users', 'new_users',
                    'total_conversations', 'total_messages', 'total_files',
                    'total_storage_used', 'avg_response_time', 'error_rate',
                    'total_revenue', 'uptime_percentage'
                )
            )
        }
        
        return data
    
    @staticmethod
    def _generate_feature_usage_report(report: Report) -> Dict[str, Any]:
        """Generate feature usage report"""
        usage = FeatureUsage.objects.filter(
            date__gte=report.start_date,
            date__lte=report.end_date
        )
        
        data = {
            'report_info': {
                'name': report.name,
                'type': report.report_type,
                'start_date': report.start_date.isoformat(),
                'end_date': report.end_date.isoformat(),
                'generated_at': timezone.now().isoformat()
            },
            'summary': usage.values('feature_name').annotate(
                total_uses=Sum('total_uses'),
                unique_users=Sum('unique_users')
            ).order_by('-total_uses'),
            'daily_breakdown': list(
                usage.values('date', 'feature_name').annotate(
                    total_uses=Sum('total_uses'),
                    unique_users=Sum('unique_users')
                ).order_by('date', 'feature_name')
            )
        }
        
        return data
    
    @staticmethod
    def _generate_error_logs_report(report: Report) -> Dict[str, Any]:
        """Generate error logs report"""
        errors = ErrorLog.objects.filter(
            created_at__date__gte=report.start_date,
            created_at__date__lte=report.end_date
        )
        
        data = {
            'report_info': {
                'name': report.name,
                'type': report.report_type,
                'start_date': report.start_date.isoformat(),
                'end_date': report.end_date.isoformat(),
                'generated_at': timezone.now().isoformat()
            },
            'summary': {
                'total_errors': errors.count(),
                'resolved_errors': errors.filter(is_resolved=True).count(),
                'unresolved_errors': errors.filter(is_resolved=False).count(),
                'error_by_level': dict(
                    errors.values('level').annotate(
                        count=Count('id')
                    ).values_list('level', 'count')
                ),
                'error_by_type': dict(
                    errors.values('exception_type').annotate(
                        count=Count('id')
                    ).values_list('exception_type', 'count')
                )
            },
            'errors': list(
                errors.values(
                    'id', 'level', 'message', 'exception_type',
                    'url', 'method', 'user__username', 'ip_address',
                    'is_resolved', 'created_at'
                ).order_by('-created_at')
            )
        }
        
        return data
    
    @staticmethod
    def _convert_to_csv(data: Dict[str, Any]) -> str:
        """Convert report data to CSV format"""
        output = io.StringIO()
        
        # Write report info
        writer = csv.writer(output)
        writer.writerow(['Report Information'])
        
        report_info = data.get('report_info', {})
        for key, value in report_info.items():
            writer.writerow([key.replace('_', ' ').title(), value])
        
        writer.writerow([])  # Empty row
        
        # Write summary
        if 'summary' in data:
            writer.writerow(['Summary'])
            summary = data['summary']
            
            if isinstance(summary, dict):
                for key, value in summary.items():
                    writer.writerow([key.replace('_', ' ').title(), value])
            
            writer.writerow([])  # Empty row
        
        # Write detailed data (first available breakdown)
        for section_name in ['daily_breakdown', 'daily_metrics', 'user_breakdown', 'errors']:
            if section_name in data and data[section_name]:
                writer.writerow([section_name.replace('_', ' ').title()])
                
                items = data[section_name]
                if items:
                    # Write headers
                    headers = list(items[0].keys())
                    writer.writerow(headers)
                    
                    # Write data
                    for item in items:
                        writer.writerow([item.get(header, '') for header in headers])
                
                break
        
        return output.getvalue()


class ErrorTrackingService:
    """Service for tracking and managing errors"""
    
    @staticmethod
    def log_error(
        level: str,
        message: str,
        exception_type: str = None,
        stack_trace: str = None,
        url: str = None,
        method: str = None,
        user=None,
        ip_address: str = None,
        user_agent: str = None,
        context: Dict = None
    ) -> ErrorLog:
        """Log an error"""
        error_log = ErrorLog.objects.create(
            level=level,
            message=message,
            exception_type=exception_type or 'Unknown',
            stack_trace=stack_trace or '',
            url=url or '',
            method=method or '',
            user=user,
            ip_address=ip_address or '',
            user_agent=user_agent or '',
            context=context or {}
        )
        
        # Track error event
        AnalyticsService.track_event(
            event_type=EventType.ERROR_OCCURRED,
            event_name=f"{level.upper()}: {exception_type or 'Error'}",
            event_description=message,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            properties={
                'error_level': level,
                'exception_type': exception_type,
                'url': url,
                'method': method
            },
            metadata=context or {},
            related_object=error_log
        )
        
        return error_log
    
    @staticmethod
    def get_error_stats(
        start_date: date = None,
        end_date: date = None
    ) -> Dict[str, Any]:
        """Get error statistics"""
        queryset = ErrorLog.objects.all()
        
        if start_date:
            queryset = queryset.filter(created_at__date__gte=start_date)
        
        if end_date:
            queryset = queryset.filter(created_at__date__lte=end_date)
        
        stats = {
            'total_errors': queryset.count(),
            'resolved_errors': queryset.filter(is_resolved=True).count(),
            'unresolved_errors': queryset.filter(is_resolved=False).count(),
            'errors_by_level': dict(
                queryset.values('level').annotate(
                    count=Count('id')
                ).values_list('level', 'count')
            ),
            'errors_by_type': dict(
                queryset.values('exception_type').annotate(
                    count=Count('id')
                ).values_list('exception_type', 'count')
            ),
            'recent_errors': list(
                queryset.order_by('-created_at')[:10].values(
                    'id', 'level', 'message', 'exception_type',
                    'created_at', 'is_resolved'
                )
            )
        }
        
        return stats