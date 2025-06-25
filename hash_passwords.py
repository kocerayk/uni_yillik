import django
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "uni_yillik.settings")
django.setup()

from users.models import GraduationYear
from django.contrib.auth.hashers import make_password

# Tüm şifreleri hashle
for year in GraduationYear.objects.all():
    if not year.password.startswith('pbkdf2_sha256$'):  # Zaten hashlenmiş olanları atla
        print(f"Hashing: {year.school.name} - {year.year}")
        year.password = make_password(year.password)
        year.save()

print("✅ Tüm şifreler başarıyla hashlenmiştir!")
