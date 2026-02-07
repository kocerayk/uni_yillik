from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from .models import School, GraduationYear

class StaticViewSitemap(Sitemap):
    priority = 0.5
    changefreq = 'monthly'

    def items(self):
        return ['profile', 'login_register', 'school_dashboard']

    def location(self, item):
        return reverse(item)

class SchoolSitemap(Sitemap):
    changefreq = 'weekly'
    priority = 0.7

    def items(self):
        return School.objects.all()

    def lastmod(self, obj):
        return obj.updated_at if hasattr(obj, 'updated_at') else None

class GraduationYearSitemap(Sitemap):
    changefreq = 'monthly'
    priority = 0.6

    def items(self):
        return GraduationYear.objects.all()

    def lastmod(self, obj):
        return None  # Mezuniyet yılları genellikle sık değişmez
