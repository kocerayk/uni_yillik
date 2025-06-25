from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.files.base import ContentFile
from .models import School
from .utils import fetch_school_logo
import requests
from io import BytesIO
import logging
from PIL import Image
import os
from django.db.models.functions import Collate

logger = logging.getLogger(__name__)

@receiver(post_save, sender=School)
def update_school_logo(sender, instance, created, **kwargs):
    """
    Signal handler to automatically fetch and set school logo when a school is created or updated.
    """
    try:
        logger.info(f"School {instance.name} {'created' if created else 'updated'}")
        
        # Skip if logo already exists and school name hasn't changed
        if instance.logo and not created and not instance.tracker.has_changed('name'):
            logger.info("School logo already exists and name hasn't changed, skipping update")
            return
            
        # Fetch logo URL
        logo_url = fetch_school_logo(instance.name)
        if not logo_url:
            logger.warning(f"No logo URL found for {instance.name}")
            return
            
        logger.info(f"Downloading logo from {logo_url}")
        response = requests.get(logo_url)
        
        if response.status_code != 200:
            logger.error(f"Failed to download logo. Status code: {response.status_code}")
            return
            
        # Process the image
        try:
            img = Image.open(BytesIO(response.content))
            
            # Convert to RGB if necessary
            if img.mode in ('RGBA', 'LA'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[-1])
                img = background
            elif img.mode != 'RGB':
                img = img.convert('RGB')
                
            # Resize if too large
            max_size = (300, 300)
            if img.size[0] > max_size[0] or img.size[1] > max_size[1]:
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
            # Save the processed image
            img_io = BytesIO()
            img.save(img_io, format='JPEG', quality=85)
            img_io.seek(0)
            
            # Save to the model
            filename = f"{instance.name.lower().replace(' ', '_')}_logo.jpg"
            instance.logo.save(filename, ContentFile(img_io.getvalue()), save=True)
            logger.info(f"Successfully saved logo for {instance.name}")
            
        except Exception as e:
            logger.error(f"Error processing image for {instance.name}: {str(e)}")
            
    except Exception as e:
        logger.error(f"Unexpected error in update_school_logo: {str(e)}") 

schools = School.objects.annotate(
    name_tr=Collate('name', 'turkish_ci')
).order_by('name_tr')