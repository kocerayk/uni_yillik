"""
URL configuration for uni_yillik project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from users import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.sitemaps.views import sitemap
from users.sitemaps import StaticViewSitemap, SchoolSitemap, GraduationYearSitemap

# Sitemap configuration
sitemaps = {
    'static': StaticViewSitemap,
    'schools': SchoolSitemap,
    'graduation_years': GraduationYearSitemap,
}

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('users.urls')),
    path('search/', views.search_users, name='search_users'),
    # Sitemap URL
    path('sitemap.xml', sitemap, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.sitemap'),
    # Account-related views
    path('login/', views.login_and_register, name='login_register'),
    path('logout/', views.user_logout, name='user_logout'),
    path('send-verification-code/', views.send_verification_code, name='send_verification_code'),
    path('verify-email-code/', views.verify_email_code, name='verify_email_code'),
    path('school-login/', views.school_login, name='school_login'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

