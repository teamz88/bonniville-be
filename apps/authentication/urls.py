from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication endpoints
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User profile endpoints
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset_password'),
    path('stats/', views.user_stats, name='user_stats'),
    
    # Admin user management endpoints
    path('users/', views.UserListView.as_view(), name='user_list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('users/<int:user_id>/upgrade-subscription/', 
         views.upgrade_user_subscription, name='upgrade_subscription'),
    
    # Session management
    path('sessions/', views.UserSessionListView.as_view(), name='session_list'),
    
    # Client information
    path('client-info/', views.ClientInfoView.as_view(), name='client_info'),
    path('client-info/status/', views.check_client_info_status, name='client_info_status'),
    path('users/<int:user_id>/client-info/', views.AdminClientInfoView.as_view(), name='admin_client_info'),
]