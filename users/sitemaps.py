from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from .models import School, GraduationYear

class StaticViewSitemap(Sitemap):
    priority = 0.5
    changefreq = 'monthly'

    def items(self):
        return ['login_register', 'yearbook']

    def location(self, item):
        return reverse(item)

class SchoolSitemap(Sitemap):
    changefreq = 'weekly'
    priority = 0.7

    def items(self):
        return School.objects.all()

    def lastmod(self, obj):
        # If you have a modified date field, use it here
        # return obj.modified_date
        return None

class GraduationYearSitemap(Sitemap):
    changefreq = 'yearly'
    priority = 0.6

    def items(self):
        return GraduationYear.objects.all()

    def lastmod(self, obj):
        # If you have a modified date field, use it here
        return None
