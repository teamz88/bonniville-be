from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db import transaction
from datetime import datetime, timedelta
import logging

from apps.analytics.models import (
    AnalyticsEvent, UserActivity, SystemMetrics, Report,
    FeatureUsage, ErrorLog
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Clean up old analytics data based on retention policies'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=365,
            help='Number of days to retain data (default: 365)'
        )
        parser.add_argument(
            '--events-days',
            type=int,
            help='Number of days to retain analytics events (overrides --days)'
        )
        parser.add_argument(
            '--activity-days',
            type=int,
            help='Number of days to retain user activity data (overrides --days)'
        )
        parser.add_argument(
            '--metrics-days',
            type=int,
            help='Number of days to retain system metrics (overrides --days)'
        )
        parser.add_argument(
            '--reports-days',
            type=int,
            help='Number of days to retain completed reports (overrides --days)'
        )
        parser.add_argument(
            '--feature-usage-days',
            type=int,
            help='Number of days to retain feature usage data (overrides --days)'
        )
        parser.add_argument(
            '--error-logs-days',
            type=int,
            help='Number of days to retain resolved error logs (overrides --days)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=1000,
            help='Number of records to delete in each batch (default: 1000)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
    
    def handle(self, *args, **options):
        try:
            if options['dry_run']:
                self.stdout.write(
                    self.style.WARNING("DRY RUN MODE - No data will be deleted")
                )
            
            # Calculate cutoff dates
            cutoff_dates = self._calculate_cutoff_dates(options)
            
            # Clean up each data type
            total_deleted = 0
            
            if cutoff_dates['events']:
                deleted = self._cleanup_analytics_events(
                    cutoff_dates['events'], options
                )
                total_deleted += deleted
            
            if cutoff_dates['activity']:
                deleted = self._cleanup_user_activity(
                    cutoff_dates['activity'], options
                )
                total_deleted += deleted
            
            if cutoff_dates['metrics']:
                deleted = self._cleanup_system_metrics(
                    cutoff_dates['metrics'], options
                )
                total_deleted += deleted
            
            if cutoff_dates['reports']:
                deleted = self._cleanup_reports(
                    cutoff_dates['reports'], options
                )
                total_deleted += deleted
            
            if cutoff_dates['feature_usage']:
                deleted = self._cleanup_feature_usage(
                    cutoff_dates['feature_usage'], options
                )
                total_deleted += deleted
            
            if cutoff_dates['error_logs']:
                deleted = self._cleanup_error_logs(
                    cutoff_dates['error_logs'], options
                )
                total_deleted += deleted
            
            action = "Would delete" if options['dry_run'] else "Deleted"
            self.stdout.write(
                self.style.SUCCESS(
                    f"{action} {total_deleted} total records"
                )
            )
            
        except Exception as e:
            logger.error(f"Error during analytics cleanup: {str(e)}")
            raise CommandError(f"Cleanup failed: {str(e)}")
    
    def _calculate_cutoff_dates(self, options):
        """Calculate cutoff dates for each data type"""
        now = timezone.now()
        default_days = options['days']
        
        cutoff_dates = {}
        
        # Analytics events
        events_days = options.get('events_days') or default_days
        cutoff_dates['events'] = now - timedelta(days=events_days)
        
        # User activity
        activity_days = options.get('activity_days') or default_days
        cutoff_dates['activity'] = now - timedelta(days=activity_days)
        
        # System metrics
        metrics_days = options.get('metrics_days') or default_days
        cutoff_dates['metrics'] = now - timedelta(days=metrics_days)
        
        # Reports
        reports_days = options.get('reports_days') or default_days
        cutoff_dates['reports'] = now - timedelta(days=reports_days)
        
        # Feature usage
        feature_usage_days = options.get('feature_usage_days') or default_days
        cutoff_dates['feature_usage'] = now - timedelta(days=feature_usage_days)
        
        # Error logs (only resolved ones)
        error_logs_days = options.get('error_logs_days') or default_days
        cutoff_dates['error_logs'] = now - timedelta(days=error_logs_days)
        
        return cutoff_dates
    
    def _cleanup_analytics_events(self, cutoff_date, options):
        """Clean up old analytics events"""
        queryset = AnalyticsEvent.objects.filter(
            created_at__lt=cutoff_date
        )
        
        total_count = queryset.count()
        
        if options['verbose']:
            self.stdout.write(
                f"Analytics Events: {total_count} records older than {cutoff_date.date()}"
            )
        
        if options['dry_run']:
            return total_count
        
        return self._delete_in_batches(
            queryset, options['batch_size'], "Analytics Events", options
        )
    
    def _cleanup_user_activity(self, cutoff_date, options):
        """Clean up old user activity data"""
        queryset = UserActivity.objects.filter(
            date__lt=cutoff_date.date()
        )
        
        total_count = queryset.count()
        
        if options['verbose']:
            self.stdout.write(
                f"User Activity: {total_count} records older than {cutoff_date.date()}"
            )
        
        if options['dry_run']:
            return total_count
        
        return self._delete_in_batches(
            queryset, options['batch_size'], "User Activity", options
        )
    
    def _cleanup_system_metrics(self, cutoff_date, options):
        """Clean up old system metrics"""
        queryset = SystemMetrics.objects.filter(
            date__lt=cutoff_date.date()
        )
        
        total_count = queryset.count()
        
        if options['verbose']:
            self.stdout.write(
                f"System Metrics: {total_count} records older than {cutoff_date.date()}"
            )
        
        if options['dry_run']:
            return total_count
        
        return self._delete_in_batches(
            queryset, options['batch_size'], "System Metrics", options
        )
    
    def _cleanup_reports(self, cutoff_date, options):
        """Clean up old completed reports"""
        queryset = Report.objects.filter(
            status='completed',
            completed_at__lt=cutoff_date
        )
        
        total_count = queryset.count()
        
        if options['verbose']:
            self.stdout.write(
                f"Completed Reports: {total_count} records older than {cutoff_date.date()}"
            )
        
        if options['dry_run']:
            return total_count
        
        # Delete associated files before deleting records
        if not options['dry_run']:
            self._cleanup_report_files(queryset, options)
        
        return self._delete_in_batches(
            queryset, options['batch_size'], "Reports", options
        )
    
    def _cleanup_feature_usage(self, cutoff_date, options):
        """Clean up old feature usage data"""
        queryset = FeatureUsage.objects.filter(
            date__lt=cutoff_date.date()
        )
        
        total_count = queryset.count()
        
        if options['verbose']:
            self.stdout.write(
                f"Feature Usage: {total_count} records older than {cutoff_date.date()}"
            )
        
        if options['dry_run']:
            return total_count
        
        return self._delete_in_batches(
            queryset, options['batch_size'], "Feature Usage", options
        )
    
    def _cleanup_error_logs(self, cutoff_date, options):
        """Clean up old resolved error logs"""
        queryset = ErrorLog.objects.filter(
            is_resolved=True,
            resolved_at__lt=cutoff_date
        )
        
        total_count = queryset.count()
        
        if options['verbose']:
            self.stdout.write(
                f"Resolved Error Logs: {total_count} records older than {cutoff_date.date()}"
            )
        
        if options['dry_run']:
            return total_count
        
        return self._delete_in_batches(
            queryset, options['batch_size'], "Error Logs", options
        )
    
    def _cleanup_report_files(self, queryset, options):
        """Clean up report files from filesystem"""
        import os
        
        for report in queryset.iterator():
            if report.file_path and os.path.exists(report.file_path):
                try:
                    os.remove(report.file_path)
                    if options['verbose']:
                        self.stdout.write(
                            f"Deleted file: {report.file_path}"
                        )
                except OSError as e:
                    logger.warning(
                        f"Failed to delete file {report.file_path}: {str(e)}"
                    )
    
    def _delete_in_batches(self, queryset, batch_size, model_name, options):
        """Delete records in batches to avoid memory issues"""
        total_deleted = 0
        
        while True:
            with transaction.atomic():
                # Get a batch of IDs
                batch_ids = list(
                    queryset.values_list('id', flat=True)[:batch_size]
                )
                
                if not batch_ids:
                    break
                
                # Delete the batch
                deleted_count = queryset.filter(id__in=batch_ids).delete()[0]
                total_deleted += deleted_count
                
                if options['verbose']:
                    self.stdout.write(
                        f"{model_name}: Deleted batch of {deleted_count} records"
                    )
        
        if options['verbose']:
            self.stdout.write(
                self.style.SUCCESS(
                    f"{model_name}: Deleted {total_deleted} total records"
                )
            )
        
        return total_deleted