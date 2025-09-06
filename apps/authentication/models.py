from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta


class User(AbstractUser):
    """Custom User model with additional fields for subscription and profile management."""
    
    class Role(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        USER = 'user', 'User'

    class SubscriptionType(models.TextChoices):
        FREE = 'free', 'Free'
        BASIC = 'basic', 'Basic'
        PREMIUM = 'premium', 'Premium'
        LIFETIME = 'lifetime', 'Lifetime'

    class SubscriptionStatus(models.TextChoices):
        ACTIVE = 'active', 'Active'
        EXPIRED = 'expired', 'Expired'
        CANCELLED = 'cancelled', 'Cancelled'
        PENDING = 'pending', 'Pending'

    # User role and permissions
    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.USER,
        help_text="User role determining access permissions"
    )

    # Subscription fields
    subscription_type = models.CharField(
        max_length=10,
        choices=SubscriptionType.choices,
        default=SubscriptionType.FREE,
        help_text="Type of subscription"
    )

    subscription_status = models.CharField(
        max_length=10,
        choices=SubscriptionStatus.choices,
        default=SubscriptionStatus.ACTIVE,
        help_text="Current subscription status"
    )

    subscription_start_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the current subscription started"
    )

    subscription_end_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the current subscription expires"
    )

    # Profile fields
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        help_text="User's phone number"
    )

    avatar = models.ImageField(
        upload_to='avatars/',
        blank=True,
        null=True,
        help_text="User's profile picture"
    )

    # Activity tracking
    last_activity = models.DateTimeField(
        auto_now=True,
        help_text="Last time user was active"
    )

    total_time_spent = models.DurationField(
        default=timedelta(0),
        help_text="Total time spent in the application"
    )

    # Preferences
    email_notifications = models.BooleanField(
        default=True,
        help_text="Whether user wants to receive email notifications"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']

    def __str__(self):
        return f"{self.username} ({self.get_full_name()})"

    @property
    def is_admin(self):
        """Check if user is an admin."""
        return self.role == self.Role.ADMIN

    @property
    def is_subscription_active(self):
        """Check if user's subscription is currently active."""
        if self.subscription_status != self.SubscriptionStatus.ACTIVE:
            return False
        
        if self.subscription_type == self.SubscriptionType.LIFETIME:
            return True
        
        if self.subscription_end_date:
            return timezone.now() <= self.subscription_end_date
        
        # If no end date is set, consider it active
        return True

    @property
    def days_until_expiry(self):
        """Get number of days until subscription expires."""
        if self.subscription_type == self.SubscriptionType.LIFETIME:
            return None
        
        if self.subscription_end_date:
            delta = self.subscription_end_date - timezone.now()
            return max(0, delta.days)
        
        return None

    def extend_subscription(self, days):
        """Extend subscription by specified number of days."""
        if self.subscription_end_date:
            self.subscription_end_date += timedelta(days=days)
        else:
            self.subscription_end_date = timezone.now() + timedelta(days=days)
        
        self.subscription_status = self.SubscriptionStatus.ACTIVE
        self.save(update_fields=['subscription_end_date', 'subscription_status'])

    def upgrade_subscription(self, new_type, duration_days=None):
        """Upgrade user's subscription to a new type."""
        self.subscription_type = new_type
        self.subscription_status = self.SubscriptionStatus.ACTIVE
        
        if new_type == self.SubscriptionType.LIFETIME:
            self.subscription_end_date = None
        elif duration_days:
            self.subscription_start_date = timezone.now()
            self.subscription_end_date = timezone.now() + timedelta(days=duration_days)
        
        self.save(update_fields=[
            'subscription_type', 
            'subscription_status', 
            'subscription_start_date', 
            'subscription_end_date'
        ])

    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        full_name = f'{self.first_name} {self.last_name}'
        return full_name.strip()


class ClientInfo(models.Model):
    """Client business information model for storing detailed business data."""
    
    PRICING_MODEL_CHOICES = [
        ('by_weight', 'By weight'),
        ('by_volume', 'By volume'),
        ('by_hour', 'By the hour'),
        ('other', 'Other'),
    ]
    
    REVENUE_RANGE_CHOICES = [
        ('0-250k', '$0 - $250,000'),
        ('250k-500k', '$250,000 - $500,000'),
        ('500k-1m', '$500,000 - $1,000,000'),
        ('1m-2m', '$1,000,000 - $2,000,000'),
        ('2m-4m', '$2,000,000 - $4,000,000'),
        ('4m+', '$4,000,000+'),
    ]
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='client_info',
        help_text="Associated user account"
    )
    
    # Basic company information
    company_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Company name"
    )
    
    owner_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Owner/Your name"
    )
    
    # Location
    state = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="State/Province"
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="City"
    )
    
    # Business details
    year_started = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text="Year business was started"
    )
    
    trucks_count = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text="Number of trucks in operation"
    )
    
    monthly_revenue = models.CharField(
        max_length=20,
        choices=REVENUE_RANGE_CHOICES,
        blank=True,
        null=True,
        help_text="Monthly revenue range"
    )
    
    gross_profit_margin = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        blank=True,
        null=True,
        help_text="Gross profit margin estimate (percentage)"
    )
    
    # Services and tools
    main_services = models.JSONField(
        default=list,
        blank=True,
        help_text="Main services offered (checklist)"
    )
    
    pricing_model = models.CharField(
        max_length=20,
        choices=PRICING_MODEL_CHOICES,
        blank=True,
        null=True,
        help_text="Pricing model used"
    )
    
    # Software and challenges
    software_tools = models.JSONField(
        default=list,
        blank=True,
        help_text="Software tools used (CRM, booking, GPS, etc.)"
    )
    
    # Challenges and completion status
    current_challenges = models.TextField(
        blank=True,
        null=True,
        help_text="Top current challenges (free text)"
    )
    
    # Completion tracking
    is_completed = models.BooleanField(
        default=False,
        help_text="Whether the client info form has been completed"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'client_info'
        verbose_name = 'Client Info'
        verbose_name_plural = 'Client Info'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Client Info for {self.user.username} - {self.company_name or 'No Company'}"


class UserSession(models.Model):
    """Model to track user sessions and activity."""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    
    session_start = models.DateTimeField(auto_now_add=True)
    session_end = models.DateTimeField(null=True, blank=True)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Activity metrics
    pages_visited = models.PositiveIntegerField(default=0)
    chat_messages_sent = models.PositiveIntegerField(default=0)
    files_uploaded = models.PositiveIntegerField(default=0)
    
    class Meta:
        db_table = 'user_sessions'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-session_start']
    
    def __str__(self):
        return f"{self.user.username} - {self.session_start.strftime('%Y-%m-%d %H:%M')}"
    
    @property
    def duration(self):
        """Calculate session duration."""
        if self.session_end:
            return self.session_end - self.session_start
        return timezone.now() - self.session_start
    
    def end_session(self):
        """End the current session and update user's total time spent."""
        if not self.session_end:
            self.session_end = timezone.now()
            self.save(update_fields=['session_end'])
            
            # Update user's total time spent
            self.user.total_time_spent += self.duration
            self.user.save(update_fields=['total_time_spent'])