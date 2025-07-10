from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from model_utils import FieldTracker


# Üniversiteleri tutan model
class School(models.Model):
    name = models.CharField(max_length=255, unique=True)  
    logo = models.ImageField(upload_to='school_logos/', blank=True, null=True)
    tracker = FieldTracker(fields=['name'])

    def __str__(self):
        return self.name
        
    def get_absolute_url(self):
        return f"/school/{self.id}/"

# Mezuniyet yıllarını tutan model
class GraduationYear(models.Model):
    year = models.PositiveIntegerField(unique=True)

    class Meta:
        ordering = ['-year']
        verbose_name = 'Mezuniyet Yılı'
        verbose_name_plural = 'Mezuniyet Yılları'

    def __str__(self):
        return str(self.year)
        
    def get_absolute_url(self):
        return f"/graduation-year/{self.year}/"

# Özel kullanıcı modelimiz
class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)  # Make email unique
    school = models.ForeignKey(School, on_delete=models.SET_NULL, null=True, blank=True)
    graduation_year = models.ForeignKey(GraduationYear, on_delete=models.SET_NULL, null=True, blank=True)
    profile_photo = models.ImageField(upload_to='profile_photos/', null=True, blank=True)
    graduation_photo = models.ImageField(upload_to='graduation_photos/', null=True, blank=True, verbose_name="Mezuniyet Fotoğrafı")
    notes_graduation_photo = models.ImageField(upload_to='notes_graduation_photos/', null=True, blank=True, verbose_name="Notlar Sayfası Mezuniyet Fotoğrafı")
    has_edited_name = models.BooleanField(default=False)
    last_name_edit_date = models.DateTimeField(null=True, blank=True)
    department = models.CharField(max_length=100, blank=True, null=True, verbose_name="Bölüm")
    has_edited_department = models.BooleanField(default=False, verbose_name="Bölüm düzenlendi mi")
    email_notifications_enabled = models.BooleanField(
        default=True,
        verbose_name="E-posta Bildirimleri Aktif",
        help_text="Yeni not aldığında e-posta bildirimi almak istiyor musunuz?"
    )

    # Use email as the username field
    USERNAME_FIELD = 'email'
    # Required fields for createsuperuser
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email  # Return email instead of username

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def get_initials(self):
        return f"{self.first_name[0]}{self.last_name[0]}" if self.first_name and self.last_name else ""


# Kullanıcılar arası mesajlar
class Message(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    visible = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.sender} → {self.receiver}"


# Kullanıcılar arası yıllığa bırakılan notlar
class Note(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="sent_notes")
    receiver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="received_notes")
    content = models.TextField()
    year = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender} → {self.receiver}"
