import os
from django.core.management.base import BaseCommand
from users.models import School
from django.core.files import File

class Command(BaseCommand):
    help = 'Import schools from the school_logos directory'

    def handle(self, *args, **options):
        logos_dir = 'media/school_logos'
        created_count = 0
        updated_count = 0

        for filename in os.listdir(logos_dir):
            if filename.endswith(('.png', '.jpg', '.jpeg')):
                # Remove file extension and clean up the name
                school_name = os.path.splitext(filename)[0]
                
                # Try to get existing school or create new one
                school, created = School.objects.get_or_create(
                    name=school_name,
                    defaults={'name': school_name}
                )
                
                # If school exists but doesn't have a logo, or if it's a new school
                if not school.logo or created:
                    logo_path = os.path.join(logos_dir, filename)
                    with open(logo_path, 'rb') as f:
                        school.logo.save(filename, File(f), save=True)
                    
                    if created:
                        created_count += 1
                        self.stdout.write(self.style.SUCCESS(f'Created school: {school_name}'))
                    else:
                        updated_count += 1
                        self.stdout.write(self.style.SUCCESS(f'Updated logo for: {school_name}'))

        self.stdout.write(self.style.SUCCESS(
            f'Successfully processed {created_count + updated_count} schools: '
            f'{created_count} created, {updated_count} updated'
        )) 