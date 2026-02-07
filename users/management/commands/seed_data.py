import csv
import os
from django.core.management.base import BaseCommand
from users.models import School, GraduationYear


class Command(BaseCommand):
    help = 'Seed schools from Schools.csv and create graduation years (2020-2030)'

    def handle(self, *args, **options):
        # Import schools from CSV
        csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'Schools.csv')
        csv_path = os.path.normpath(csv_path)

        if not os.path.exists(csv_path):
            self.stderr.write(self.style.ERROR(f'Schools.csv not found at {csv_path}'))
            return

        created_schools = 0
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row
            for row in reader:
                if row and row[0].strip():
                    school_name = row[0].strip()
                    _, created = School.objects.get_or_create(name=school_name)
                    if created:
                        created_schools += 1

        self.stdout.write(self.style.SUCCESS(f'Schools: {created_schools} created'))

        # Create graduation years
        created_years = 0
        for year in range(2000, 2031):
            _, created = GraduationYear.objects.get_or_create(year=year)
            if created:
                created_years += 1

        self.stdout.write(self.style.SUCCESS(f'Graduation years: {created_years} created'))
