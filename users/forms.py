from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, School, GraduationYear


class CustomUserRegistrationForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=30,
        required=True,
        label="Ad",
        widget=forms.TextInput(attrs={'autocomplete': 'given-name'})
    )
    last_name = forms.CharField(
        max_length=30,
        required=True,
        label="Soyad",
        widget=forms.TextInput(attrs={'autocomplete': 'family-name'})
    )
    graduation_year = forms.ModelChoiceField(
        queryset=GraduationYear.objects.all().order_by('-year'),
        required=True,
        label="Mezuniyet Yılı",
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    email = forms.EmailField(
        max_length=254,
        required=True,
        label="E-posta",
        widget=forms.EmailInput(attrs={'autocomplete': 'email'})
    )

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'graduation_year', 'password1', 'password2')

    def clean(self):
        cleaned_data = super().clean()
        first_name = cleaned_data.get('first_name', '').strip().lower()
        last_name = cleaned_data.get('last_name', '').strip().lower()

        if not first_name or not last_name:
            raise forms.ValidationError("Ad ve soyad alanları boş bırakılamaz.")

        # Generate username here but don't set it yet
        username = f"{first_name}.{last_name}"

        # Check if username exists
        counter = 1
        temp_username = username
        while CustomUser.objects.filter(username=temp_username).exists():
            temp_username = f"{username}{counter}"
            counter += 1

        # Store the final username in cleaned_data for use in save()
        cleaned_data['generated_username'] = temp_username

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.first_name = self.cleaned_data.get("first_name")
        user.last_name = self.cleaned_data.get("last_name")
        user.email = self.cleaned_data.get("email")
        user.graduation_year = self.cleaned_data.get("graduation_year")
        user.username = self.cleaned_data.get("generated_username")

        if commit:
            try:
                user.save()
            except Exception as e:
                raise forms.ValidationError(f"Kullanıcı kaydedilirken bir hata oluştu: {e}")

        return user


# Diğer formlar olduğu gibi kalabilir...
class SchoolAccessForm(forms.Form):
    school = forms.ModelChoiceField(queryset=School.objects.all(), label="Okul Seçin")
    password = forms.CharField(widget=forms.PasswordInput, label="Okul Şifresi")

class SchoolLoginForm(forms.Form):
    school_name = forms.CharField(max_length=255, label="Okul Adı")
    graduation_year = forms.IntegerField(label="Mezuniyet Yılı")
    password = forms.CharField(widget=forms.PasswordInput, label="Okul Şifresi")

    def clean(self):
        cleaned_data = super().clean()
        school_name = cleaned_data.get('school_name')
        graduation_year = cleaned_data.get('graduation_year')
        password = cleaned_data.get('password')

        try:
            school = School.objects.get(name=school_name)
            graduation_year_obj = GraduationYear.objects.get(school=school, year=graduation_year)
        except School.DoesNotExist:
            raise forms.ValidationError("Okul bulunamadı.")
        except GraduationYear.DoesNotExist:
            raise forms.ValidationError("Mezuniyet yılı bulunamadı.")

        if graduation_year_obj.password != password:
            raise forms.ValidationError("Şifre yanlış.")

        return cleaned_data

class UserSearchForm(forms.Form):
    username = forms.CharField(required=False)
    school = forms.CharField(required=False)
    year = forms.IntegerField(required=False)

# Bireysel kullanıcı girişi için login formu
class LoginForm(forms.Form):
    email = forms.EmailField(
        label="E-posta",
        max_length=254,
        widget=forms.EmailInput(attrs={'autocomplete': 'email'})
    )
    password = forms.CharField(label="Şifre", widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data

