import os
import django
import sys

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'uni_yillik.settings')
django.setup()

from users.models import School
from django.core.files import File

def import_schools():
    logos_dir = 'media/school_logos'
    created_count = 0
    updated_count = 0

    for filename in os.listdir(logos_dir):
        if filename.endswith(('.png', '.jpg', '.jpeg')):
            # Remove file extension and clean up the name
            school_name = os.path.splitext(filename)[0]
            
            print(f"Processing: {school_name}")
            
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
                    print(f'Created school: {school_name}')
                else:
                    updated_count += 1
                    print(f'Updated logo for: {school_name}')

    print(f'Successfully processed {created_count + updated_count} schools: '
          f'{created_count} created, {updated_count} updated')

if __name__ == '__main__':
    import_schools() 