from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from .models import User, UserSession


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User admin interface."""
    
    list_display = (
        'username', 'email', 'full_name', 'role',
        'subscription_type', 'subscription_status_badge',
        'is_subscription_active', 'date_joined', 'is_active'
    )
    
    list_filter = (
        'role', 'subscription_type', 'subscription_status',
        'is_active', 'date_joined', 'last_login'
    )
    
    search_fields = ('username', 'email', 'first_name', 'last_name')
    
    ordering = ('-date_joined',)
    
    readonly_fields = (
        'date_joined', 'last_login', 'last_activity',
        'total_time_spent', 'is_subscription_active',
        'days_until_expiry'
    )
    
    fieldsets = (
        (None, {
            'fields': ('username', 'password')
        }),
        ('Personal info', {
            'fields': (
                'first_name', 'last_name', 'email',
                'phone_number', 'avatar'
            )
        }),
        ('Permissions', {
            'fields': (
                'role', 'is_active', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
            )
        }),
        ('Subscription', {
            'fields': (
                'subscription_type', 'subscription_status',
                'subscription_start_date', 'subscription_end_date',
                'is_subscription_active', 'days_until_expiry'
            )
        }),
        ('Preferences', {
            'fields': ('email_notifications',)
        }),
        ('Activity', {
            'fields': (
                'date_joined', 'last_login', 'last_activity',
                'total_time_spent'
            )
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'email', 'password1', 'password2',
                'first_name', 'last_name', 'role'
            ),
        }),
    )
    
    def full_name(self, obj):
        """Display user's full name."""
        return obj.get_full_name()
    full_name.short_description = 'Full Name'
    
    def subscription_status_badge(self, obj):
        """Display subscription status with color coding."""
        colors = {
            'active': 'green',
            'expired': 'red',
            'cancelled': 'orange',
            'pending': 'blue'
        }
        color = colors.get(obj.subscription_status, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_subscription_status_display()
        )
    subscription_status_badge.short_description = 'Status'
    
    actions = ['activate_users', 'deactivate_users', 'upgrade_to_premium']
    
    def activate_users(self, request, queryset):
        """Activate selected users."""
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            f'{updated} users were successfully activated.'
        )
    activate_users.short_description = 'Activate selected users'
    
    def deactivate_users(self, request, queryset):
        """Deactivate selected users."""
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            f'{updated} users were successfully deactivated.'
        )
    deactivate_users.short_description = 'Deactivate selected users'
    
    def upgrade_to_premium(self, request, queryset):
        """Upgrade selected users to premium."""
        updated = 0
        for user in queryset:
            if user.subscription_type != User.SubscriptionType.PREMIUM:
                user.upgrade_subscription(User.SubscriptionType.PREMIUM, 365)
                updated += 1
        
        self.message_user(
            request,
            f'{updated} users were upgraded to premium.'
        )
    upgrade_to_premium.short_description = 'Upgrade to Premium (1 year)'


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """User Session admin interface."""
    
    list_display = (
        'user', 'session_start', 'session_end', 'duration_display',
        'ip_address', 'pages_visited', 'chat_messages_sent',
        'files_uploaded'
    )
    
    list_filter = (
        'session_start', 'session_end', 'user__role'
    )
    
    search_fields = (
        'user__username', 'user__email', 'ip_address'
    )
    
    readonly_fields = (
        'session_start', 'duration_display', 'user_agent'
    )
    
    ordering = ('-session_start',)
    
    def duration_display(self, obj):
        """Display session duration in a readable format."""
        duration = obj.duration
        if duration:
            total_seconds = int(duration.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        return "Active"
    duration_display.short_description = 'Duration'
    
    def has_add_permission(self, request):
        """Disable adding sessions manually."""
        return False