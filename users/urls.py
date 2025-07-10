from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from django.shortcuts import redirect
from users import views
from django.contrib.sitemaps.views import sitemap
from users.sitemaps import StaticViewSitemap, SchoolSitemap, GraduationYearSitemap

def home_redirect(request):
    """Redirect root URL to appropriate page based on authentication status"""
    if request.user.is_authenticated:
        return redirect('school_dashboard')
    else:
        return redirect('login_register')

sitemaps = {
    'static': StaticViewSitemap,
    'schools': SchoolSitemap,
    'graduation_years': GraduationYearSitemap,
}

urlpatterns = [
    # Root URL pattern
    path('', home_redirect, name='home'),
    
    path('admin/', admin.site.urls),

    # SEO related
    path('sitemap.xml', sitemap, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.sitemap'),
    path('robots.txt', views.robots_txt, name='robots_txt'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/update-photo/', views.update_profile_photo, name='update_profile_photo'),
    path('profile/update-graduation-photo/', views.update_graduation_photo, name='update_graduation_photo'),
    path('profile/update-notes-graduation-photo/', views.update_notes_graduation_photo, name='update_notes_graduation_photo'),
    path('profile/update/personal/', views.update_personal_info, name='update_personal_info'),
    path('profile/cleanup-photo/', views.cleanup_photo, name='cleanup_photo'),
    path('school_dashboard/', views.school_dashboard, name='school_dashboard'),
    path('send-message/<int:receiver_id>/', views.send_message, name='send_message'),
    path('my-notes/', views.my_notes, name='my_notes'),
    path('message/toggle-visibility/<int:message_id>/', views.toggle_message_visibility, name='toggle_message_visibility'),
    path('edit-message/<int:message_id>/', views.edit_message, name='edit_message'),
    path('delete-message/<int:pk>/', views.delete_message, name='delete_message'),
    path('delete-sent-message/<int:pk>/', views.delete_sent_message, name='delete_sent_message'),
    path('settings/', views.settings_view, name='settings_view'),
    path('feedback/', views.feedback_view, name='feedback_view'),
    path('download-user-data/', views.download_user_data, name='download_user_data'),
    path('search/', views.search_users, name='search_users'),

    # Email verification
    path('send-verification-code/', views.send_verification_code, name='send_verification_code'),
    
    # Login and Register view (using login_and_register)
    path('login/', views.login_and_register, name='login_register'),
    path('logout/', views.user_logout, name='user_logout'),
    path('send-verification-code/', views.send_verification_code, name='send_verification_code'),
    path('verify-email-code/', views.verify_email_code, name='verify_email_code'),
    path('school-login/', views.school_login, name='school_login'),

    # Other user pages
    path('friend/<int:friend_id>/', views.friend_profile, name='friend_profile'),
    path('view-friend/<int:friend_id>/', views.view_friend, name='view_friend'),
    path('yearbook/', views.yearbook, name='yearbook'),
    path('delete-account/', views.delete_account, name='delete_account'),

    # Password reset URLs
    path('password_reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', views.UnifiedPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.UnifiedPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', views.UnifiedPasswordResetCompleteView.as_view(), name='password_reset_complete'),
         
    # Email notifications
    path('settings/update-email-notifications/',
         views.update_email_notifications,
         name='update_email_notifications'),

    path('get-graduation-years/', views.get_graduation_years, name='get_graduation_years'),
]
