from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db.models import Count, Sum, Avg
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
import logging

from apps.analytics.models import SystemMetrics, AnalyticsEvent, UserActivity
from apps.chat.models import Conversation, ChatMessage
from apps.files.models import File

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Generate system metrics for a specific date or date range'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date to generate metrics for (YYYY-MM-DD format). Defaults to yesterday.'
        )
        parser.add_argument(
            '--start-date',
            type=str,
            help='Start date for date range (YYYY-MM-DD format)'
        )
        parser.add_argument(
            '--end-date',
            type=str,
            help='End date for date range (YYYY-MM-DD format)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force regeneration of existing metrics'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
    
    def handle(self, *args, **options):
        try:
            # Parse date arguments
            dates = self._parse_dates(options)
            
            if options['verbose']:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Generating metrics for {len(dates)} date(s)..."
                    )
                )
            
            # Generate metrics for each date
            for date in dates:
                self._generate_metrics_for_date(date, options)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully generated metrics for {len(dates)} date(s)"
                )
            )
            
        except Exception as e:
            logger.error(f"Error generating system metrics: {str(e)}")
            raise CommandError(f"Failed to generate metrics: {str(e)}")
    
    def _parse_dates(self, options):
        """Parse date arguments and return list of dates to process"""
        dates = []
        
        if options['start_date'] and options['end_date']:
            # Date range
            try:
                start_date = datetime.strptime(options['start_date'], '%Y-%m-%d').date()
                end_date = datetime.strptime(options['end_date'], '%Y-%m-%d').date()
                
                if start_date > end_date:
                    raise CommandError("Start date must be before end date")
                
                current_date = start_date
                while current_date <= end_date:
                    dates.append(current_date)
                    current_date += timedelta(days=1)
                    
            except ValueError:
                raise CommandError("Invalid date format. Use YYYY-MM-DD")
                
        elif options['date']:
            # Single date
            try:
                date = datetime.strptime(options['date'], '%Y-%m-%d').date()
                dates.append(date)
            except ValueError:
                raise CommandError("Invalid date format. Use YYYY-MM-DD")
                
        else:
            # Default to yesterday
            yesterday = timezone.now().date() - timedelta(days=1)
            dates.append(yesterday)
        
        return dates
    
    def _generate_metrics_for_date(self, date, options):
        """Generate system metrics for a specific date"""
        if options['verbose']:
            self.stdout.write(f"Processing date: {date}")
        
        # Check if metrics already exist
        existing_metrics = SystemMetrics.objects.filter(date=date).first()
        if existing_metrics and not options['force']:
            if options['verbose']:
                self.stdout.write(
                    self.style.WARNING(
                        f"Metrics for {date} already exist. Use --force to regenerate."
                    )
                )
            return
        
        # Calculate date range for the day
        start_datetime = timezone.make_aware(
            datetime.combine(date, datetime.min.time())
        )
        end_datetime = timezone.make_aware(
            datetime.combine(date, datetime.max.time())
        )
        
        # Calculate user metrics
        user_metrics = self._calculate_user_metrics(date, start_datetime, end_datetime)
        
        # Calculate content metrics
        content_metrics = self._calculate_content_metrics(date, start_datetime, end_datetime)
        
        # Calculate performance metrics
        performance_metrics = self._calculate_performance_metrics(date, start_datetime, end_datetime)
        
        # Calculate revenue metrics (placeholder - implement based on your billing system)
        revenue_metrics = self._calculate_revenue_metrics(date, start_datetime, end_datetime)
        
        # Create or update metrics
        metrics_data = {
            **user_metrics,
            **content_metrics,
            **performance_metrics,
            **revenue_metrics,
            'date': date,
        }
        
        if existing_metrics:
            for key, value in metrics_data.items():
                setattr(existing_metrics, key, value)
            existing_metrics.save()
            action = "Updated"
        else:
            SystemMetrics.objects.create(**metrics_data)
            action = "Created"
        
        if options['verbose']:
            self.stdout.write(
                self.style.SUCCESS(f"{action} metrics for {date}")
            )
    
    def _calculate_user_metrics(self, date, start_datetime, end_datetime):
        """Calculate user-related metrics"""
        # Total users up to this date
        total_users = User.objects.filter(
            date_joined__lte=end_datetime
        ).count()
        
        # New users on this date
        new_users = User.objects.filter(
            date_joined__gte=start_datetime,
            date_joined__lte=end_datetime
        ).count()
        
        # Active users on this date (users who performed any action)
        active_users = UserActivity.objects.filter(
            date=date
        ).values('user').distinct().count()
        
        # Premium users (assuming you have a way to identify them)
        # This is a placeholder - implement based on your subscription system
        premium_users = User.objects.filter(
            date_joined__lte=end_datetime,
            # Add your premium user filter here
            # e.g., subscription__is_active=True
        ).count()
        
        return {
            'total_users': total_users,
            'active_users': active_users,
            'new_users': new_users,
            'premium_users': premium_users,
        }
    
    def _calculate_content_metrics(self, date, start_datetime, end_datetime):
        """Calculate content-related metrics"""
        # Total conversations up to this date
        total_conversations = Conversation.objects.filter(
            created_at__lte=end_datetime
        ).count()
        
        # Total messages up to this date
        total_messages = ChatMessage.objects.filter(
            created_at__lte=end_datetime
        ).count()
        
        # Total files up to this date
        total_files = File.objects.filter(
            created_at__lte=end_datetime
        ).count()
        
        # Total storage used
        total_storage = File.objects.filter(
            created_at__lte=end_datetime
        ).aggregate(
            total=Sum('file_size')
        )['total'] or 0
        
        return {
            'total_conversations': total_conversations,
            'total_messages': total_messages,
            'total_files': total_files,
            'total_storage_used': total_storage,
        }
    
    def _calculate_performance_metrics(self, date, start_datetime, end_datetime):
        """Calculate performance-related metrics"""
        # API calls on this date
        api_calls = AnalyticsEvent.objects.filter(
            created_at__gte=start_datetime,
            created_at__lte=end_datetime,
            event_type='api_call'
        ).count()
        
        # Error events on this date
        error_events = AnalyticsEvent.objects.filter(
            created_at__gte=start_datetime,
            created_at__lte=end_datetime,
            event_type='error_occurred'
        ).count()
        
        # Calculate error rate
        total_requests = api_calls + error_events
        error_rate = (error_events / total_requests * 100) if total_requests > 0 else 0
        
        # Average response time (placeholder - implement based on your monitoring)
        avg_response_time = 150.0  # milliseconds
        
        # Uptime percentage (placeholder - implement based on your monitoring)
        uptime_percentage = 99.9
        
        return {
            'total_api_calls': api_calls,
            'error_rate': error_rate,
            'avg_response_time': avg_response_time,
            'uptime_percentage': uptime_percentage,
        }
    
    def _calculate_revenue_metrics(self, date, start_datetime, end_datetime):
        """Calculate revenue-related metrics"""
        # Placeholder implementation
        # Implement based on your billing/subscription system
        
        return {
            'total_revenue': 0.0,
            'new_subscriptions': 0,
            'cancelled_subscriptions': 0,
        }
    
    def _log_metrics_summary(self, metrics, date):
        """Log a summary of generated metrics"""
        self.stdout.write(
            f"Metrics for {date}:\n"
            f"  Users: {metrics['total_users']} total, "
            f"{metrics['active_users']} active, {metrics['new_users']} new\n"
            f"  Content: {metrics['total_conversations']} conversations, "
            f"{metrics['total_messages']} messages, {metrics['total_files']} files\n"
            f"  Performance: {metrics['total_api_calls']} API calls, "
            f"{metrics['error_rate']:.2f}% error rate\n"
        )