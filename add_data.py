import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "uni_yillik.settings")
django.setup()

from users.models import School, GraduationYear

# Okul ve dönem verileri
schools = [
    ("Boğaziçi Üniversitesi", 2025),
    ("İstanbul Teknik Üniversitesi", 2024),
    ("Orta Doğu Teknik Üniversitesi", 2026),
    ("Hacettepe Üniversitesi", 2023)
]

for school_name, year in schools:
    school, created = School.objects.get_or_create(name=school_name)
    GraduationYear.objects.get_or_create(school=school, year=year)
    print(f"{school_name} - {year} eklendi!")
