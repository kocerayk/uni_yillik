import os
import csv
import shutil
from django.core.management.base import BaseCommand
from django.core.files import File
from django.conf import settings
from users.models import School
from PIL import Image
import re

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
        parser.add_argument(
            '--clear-first',
            action='store_true',
            help='Clear all existing schools before import'
        )

    def handle(self, *args, **options):
        # Mevcut okulları temizle (istenirse)
        if options['clear_first']:
            count = School.objects.count()
            School.objects.all().delete()
            self.stdout.write(f'Cleared {count} existing schools')

        csv_path = options['csv_path']
        logos_path = options['logos_path']
        
        # CSV dosyasının varlığını kontrol et
        if not os.path.exists(csv_path):
            self.stdout.write(
                self.style.ERROR(f'CSV file not found: {csv_path}')
            )
            return
        
        # Logo klasörünün varlığını kontrol et
        logo_files = {}
        if logos_path and os.path.exists(logos_path):
            for filename in os.listdir(logos_path):
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    # Dosya adından uzantıyı çıkar ve temizle
                    name_without_ext = os.path.splitext(filename)[0]
                    # Türkçe karakterleri normalize et
                    clean_name = self.normalize_school_name(name_without_ext)
                    logo_files[clean_name] = filename

            self.stdout.write(f'Found {len(logo_files)} logo files')
        else:
            self.stdout.write(
                self.style.WARNING(f'Logos directory not found: {logos_path}')
            )

        # CSV dosyasını oku
        schools_created = 0
        schools_with_logo = 0
        schools_without_logo = 0

        self.stdout.write('Starting CSV import...')

        try:
            # Farklı encoding'leri dene
            encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
            csv_content = None
            
            for encoding in encodings:
                try:
                    with open(csv_path, 'r', encoding=encoding) as csvfile:
                        csv_content = csvfile.read()
                        self.stdout.write(f'Successfully read CSV with encoding: {encoding}')
                        break
                except UnicodeDecodeError:
                    continue
            
            if not csv_content:
                self.stdout.write(self.style.ERROR('Could not read CSV file with any encoding'))
                return

            # CSV'yi parse et
            lines = csv_content.strip().split('\n')
            if not lines:
                self.stdout.write(self.style.ERROR('CSV file is empty'))
                return

            # Header'ı kontrol et
            header = lines[0].split(',')
            self.stdout.write(f'CSV headers: {header}')
            
            # "School Name" sütununu bul
            school_name_col = None
            for i, col in enumerate(header):
                if 'school' in col.lower() and 'name' in col.lower():
                    school_name_col = i
                    break
            
            if school_name_col is None:
                self.stdout.write(self.style.ERROR('Could not find school name column'))
                return

            # Veriyi işle
            for row_num, line in enumerate(lines[1:], 1):
                if not line.strip():
                    continue
                    
                # CSV satırını parse et
                row = [cell.strip().strip('"') for cell in line.split(',')]
                
                if len(row) <= school_name_col:
                    continue
                    
                school_name = row[school_name_col].strip()
                if not school_name:
                    continue

                self.stdout.write(f'Processing ({row_num}): {school_name}')

                # Okul oluştur
                school, created = School.objects.get_or_create(
                    name=school_name,
                    defaults={'name': school_name}
                )

                if not created:
                    self.stdout.write(f'  ⚠ School already exists, skipping: {school_name}')
                    continue

                schools_created += 1

                # Logo dosyasını bul
                logo_assigned = False
                if logo_files:
                    normalized_school_name = self.normalize_school_name(school_name)
                    
                    # Tam eşleşme ara
                    if normalized_school_name in logo_files:
                        logo_filename = logo_files[normalized_school_name]
                        logo_assigned = self.assign_logo(school, logos_path, logo_filename)
                    else:
                        # Kısmi eşleşme ara
                        for logo_key, logo_file in logo_files.items():
                            if (len(logo_key) > 5 and logo_key in normalized_school_name) or \
                               (len(normalized_school_name) > 5 and normalized_school_name in logo_key):
                                logo_filename = logo_file
                                logo_assigned = self.assign_logo(school, logos_path, logo_filename)
                                break

                if logo_assigned:
                    schools_with_logo += 1
                    self.stdout.write(f'  ✓ Logo assigned')
                else:
                    schools_without_logo += 1
                    self.stdout.write(f'  ⚠ No logo found')

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error processing CSV: {e}')
            )
            return

        # Özet
        self.stdout.write(
            self.style.SUCCESS(
                f'\n--- Import Summary ---\n'
                f'Schools created: {schools_created}\n'
                f'Schools with logo: {schools_with_logo}\n'
                f'Schools without logo: {schools_without_logo}\n'
                f'Total in database: {School.objects.count()}'
            )
        )

    def assign_logo(self, school, logos_path, logo_filename):
        """Okula logo ata"""
        try:
            source_path = os.path.join(logos_path, logo_filename)
            
            if not os.path.exists(source_path):
                return False
                
            # Media klasörüne kopyala
            media_logos_dir = os.path.join(settings.MEDIA_ROOT, 'school_logos')
            os.makedirs(media_logos_dir, exist_ok=True)
            
            # Dosya adını düzenle
            clean_filename = self.clean_filename(logo_filename)
            destination_path = os.path.join(media_logos_dir, clean_filename)
            
            # Resmi kopyala
            shutil.copy2(source_path, destination_path)
            
            # Resmi optimize et
            self.optimize_image(destination_path)
            
            # Model alanını güncelle
            school.logo = f'school_logos/{clean_filename}'
            school.save()
            
            self.stdout.write(f'    Logo: {logo_filename} -> {clean_filename}')
            return True
            
        except Exception as e:
            self.stdout.write(f'    Logo assignment failed: {e}')
            return False

    def normalize_school_name(self, name):
        """Okul adını normalize et - karşılaştırma için"""
        # Türkçe karakterleri değiştir
        char_map = {
            'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u',
            'Ç': 'C', 'Ğ': 'G', 'İ': 'I', 'Ö': 'O', 'Ş': 'S', 'Ü': 'U'
        }
        
        normalized = name.lower()
        for turkish_char, english_char in char_map.items():
            normalized = normalized.replace(turkish_char.lower(), english_char)
        
        # Özel karakterleri ve boşlukları temizle
        normalized = re.sub(r'[^\w]', '', normalized)
        
        return normalized

    def clean_filename(self, filename):
        """Dosya adını temizle"""
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
        """Resmi optimize et (boyut küçültme)
        
        Args:
            image_path (str): Optimize edilecek resmin dosya yolu
            
        Returns:
            bool: İşlem başarılı olduysa True, aksi halde False
        """
        try:
            with Image.open(image_path) as img:
                # Maksimum boyut belirle
                max_size = (300, 300)
                
                # Oranı koru
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                # Kaliteyi ayarla ve kaydet
                img.save(image_path, optimize=True, quality=85)
                return True
                
        except Exception as e:
            self.stdout.write(f'  ⚠ Image optimization failed for {os.path.basename(image_path)}: {str(e)}')
            return False