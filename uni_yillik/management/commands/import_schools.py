import os
import csv
import shutil
from django.core.management.base import BaseCommand
from django.core.files import File
from django.conf import settings
from uni_yillik.models import School  # Model adınızı kontrol edin
from PIL import Image

class Command(BaseCommand):
    help = 'Import schools from CSV file and match with logos'

    def add_arguments(self, parser):
        parser.add_argument(
            '--csv-path',
            type=str,
            default='Schools.csv',
            help='Path to CSV file containing school names'
        )
        parser.add_argument(
            '--logos-path',
            type=str,
            default=r'C:\Users\90531\Desktop\uni_yillik\media\school_logos',
            help='Path to directory containing school logos'
        )

    def handle(self, *args, **options):
        csv_path = options['csv_path']
        logos_path = options['logos_path']
        
        # CSV dosyasının varlığını kontrol et
        if not os.path.exists(csv_path):
            self.stdout.write(
                self.style.ERROR(f'CSV file not found: {csv_path}')
            )
            return
        
        # Logo klasörünün varlığını kontrol et
        if not os.path.exists(logos_path):
            self.stdout.write(
                self.style.ERROR(f'Logos directory not found: {logos_path}')
            )
            return

        # Mevcut logo dosyalarını listele
        logo_files = {}
        for filename in os.listdir(logos_path):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                # Dosya adından uzantıyı çıkar
                name_without_ext = os.path.splitext(filename)[0]
                logo_files[name_without_ext.lower()] = filename

        self.stdout.write(f'Found {len(logo_files)} logo files')

        # CSV dosyasını oku
        schools_created = 0
        schools_updated = 0
        schools_without_logo = 0

        try:
            with open(csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                if 'School Name' not in reader.fieldnames:
                    self.stdout.write(
                        self.style.ERROR('CSV file must have "School Name" column')
                    )
                    return

                for row in reader:
                    school_name = row['School Name'].strip()
                    if not school_name:
                        continue

                    # Okul var mı kontrol et
                    school, created = School.objects.get_or_create(
                        name=school_name,
                        defaults={
                            'name': school_name,
                            # Diğer varsayılan alanlarınız varsa buraya ekleyin
                        }
                    )

                    # Logo dosyasını bul
                    logo_filename = None
                    school_name_lower = school_name.lower()
                    
                    # Tam eşleşme ara
                    if school_name_lower in logo_files:
                        logo_filename = logo_files[school_name_lower]
                    else:
                        # Kısmi eşleşme ara
                        for logo_key, logo_file in logo_files.items():
                            if logo_key in school_name_lower or school_name_lower in logo_key:
                                logo_filename = logo_file
                                break

                    # Logo dosyasını kopyala ve ata
                    if logo_filename:
                        source_path = os.path.join(logos_path, logo_filename)
                        
                        # Media klasörüne kopyala
                        media_logos_dir = os.path.join(settings.MEDIA_ROOT, 'school_logos')
                        os.makedirs(media_logos_dir, exist_ok=True)
                        
                        # Dosya adını düzenle (özel karakterleri temizle)
                        clean_filename = self.clean_filename(logo_filename)
                        destination_path = os.path.join(media_logos_dir, clean_filename)
                        
                        try:
                            # Resmi kopyala
                            shutil.copy2(source_path, destination_path)
                            
                            # Resmi optimize et (isteğe bağlı)
                            self.optimize_image(destination_path)
                            
                            # Model alanını güncelle (logo field adınızı kontrol edin)
                            school.logo = f'school_logos/{clean_filename}'
                            school.save()
                            
                            self.stdout.write(f'✓ {school_name} - Logo: {logo_filename}')
                        except Exception as e:
                            self.stdout.write(
                                self.style.WARNING(f'Logo copy failed for {school_name}: {e}')
                            )
                    else:
                        schools_without_logo += 1
                        self.stdout.write(
                            self.style.WARNING(f'⚠ {school_name} - Logo not found')
                        )

                    if created:
                        schools_created += 1
                    else:
                        schools_updated += 1

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error reading CSV file: {e}')
            )
            return

        # Özet
        self.stdout.write(
            self.style.SUCCESS(
                f'\n--- Import Summary ---\n'
                f'Schools created: {schools_created}\n'
                f'Schools updated: {schools_updated}\n'
                f'Schools without logo: {schools_without_logo}\n'
                f'Total processed: {schools_created + schools_updated}'
            )
        )

    def clean_filename(self, filename):
        """Dosya adını temizle"""
        import re
        # Türkçe karakterleri değiştir
        char_map = {
            'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
            'Ç': 'C', 'Ğ': 'G', 'İ': 'I', 'Ö': 'O', 'Ş': 'S', 'Ü': 'U'
        }
        
        for turkish_char, english_char in char_map.items():
            filename = filename.replace(turkish_char, english_char)
        
        # Özel karakterleri temizle
        filename = re.sub(r'[^\w\s.-]', '', filename)
        filename = re.sub(r'\s+', '_', filename)
        
        return filename

    def optimize_image(self, image_path):
        """Resmi optimize et (boyut küçültme)"""
        try:
            with Image.open(image_path) as img:
                # Maksimum boyut belirle
                max_size = (300, 300)
                
                # Oranı koru
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                # Kaliteyi ayarla ve kaydet
                img.save(image_path, optimize=True, quality=85)
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'Image optimization failed: {e}')
            )
