import json
import random
import string
import time
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.db import IntegrityError
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .models import School, GraduationYear
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy, reverse
from django.contrib import messages
from django.contrib.auth.hashers import check_password
from django.db.models.functions import Collate
from django.db import IntegrityError
import json
# forms.py içindeki formları doğru şekilde import ettiğinizden emin olun.
from .forms import CustomUserRegistrationForm, LoginForm, UserSearchForm
from .models import Message, CustomUser, School, GraduationYear, Note
from django.core.mail import send_mail
from django.conf import settings
import random
import string
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.views.decorators.http import require_POST, require_http_methods
import os
import logging
import json
from django.core.files.storage import default_storage
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import requests
from urllib.parse import urljoin
from django.core.exceptions import SuspiciousFileOperation

logger = logging.getLogger(__name__)

@login_required
@require_http_methods(["POST"])
def delete_account(request):
    """
    Kullanıcının hesabını tamamen siler
    """
    user = request.user
    
    try:
        # Kullanıcıyı çıkış yap
        logout(request)
        
        # Kullanıcı hesabını sil
        user.delete()
        
        # Başarı mesajı (session'da saklanır çünkü kullanıcı çıkış yapmış)
        messages.success(request, 'Hesabınız başarıyla silindi.')
        
        # Ana sayfaya yönlendir
        return redirect('home')  # veya 'login' sayfasına yönlendirebilirsiniz
        
    except Exception as e:
        logger.error(f"Error deleting account: {str(e)}")
        messages.error(request, 'Hesap silinirken bir hata oluştu. Lütfen tekrar deneyin.')
        return redirect('settings_view')

# Turkish character mapping for sorting
TURKISH_CHAR_MAP = {
    'ı': 'i', 'İ': 'I',
    'ğ': 'g', 'Ğ': 'G',
    'ü': 'u', 'Ü': 'U',
    'ş': 's', 'Ş': 'S',
    'ö': 'o', 'Ö': 'O',
    'ç': 'c', 'Ç': 'C',
}

def turkish_sort_key(name):
    """Convert Turkish characters to their ASCII equivalents for sorting."""
    for tr_char, ascii_char in TURKISH_CHAR_MAP.items():
        name = name.replace(tr_char, ascii_char)
    return name.lower()

# ----------------------------------------------------------------------
# Giriş ve Kayıt İşlemini Aynı Sayfada Yürüten View
# ----------------------------------------------------------------------
from django.http import JsonResponse
from django.urls import reverse


@csrf_exempt
@require_http_methods(["POST"])
def send_verification_code(request):
    try:
        print("\n=== SEND VERIFICATION CODE ===")
        print(f"Request method: {request.method}")
        print(f"Request headers: {dict(request.headers)}")
        print(f"Request body: {request.body}")
        print(f"Session ID: {request.session.session_key}")
        
        # Ensure session is created if it doesn't exist
        if not request.session.session_key:
            request.session.create()
            print(f"Created new session with ID: {request.session.session_key}")
        
        # Parse JSON data from request body
        try:
            data = json.loads(request.body)
            print(f"Request data: {data}")
        except json.JSONDecodeError as e:
            print(f"Invalid JSON data received: {str(e)}")
            return JsonResponse({
                'success': False, 
                'error': 'Geçersiz veri formatı. Lütfen tekrar deneyin.'
            })
            
        email = data.get('email', '').strip().lower()
        
        if not email:
            print("No email provided")
            return JsonResponse({
                'success': False, 
                'error': 'E-posta adresi gerekli'
            })
            
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            print(f"Invalid email format: {email}")
            return JsonResponse({
                'success': False, 
                'error': 'Geçersiz e-posta formatı. Lütfen geçerli bir e-posta adresi girin.'
            })
            
        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            print(f"Email already exists: {email}")
            return JsonResponse({
                'success': False, 
                'error': 'Bu e-posta adresi zaten kullanılıyor. Giriş yapmayı deneyin.'
            })
        
        # Generate a 6-digit verification code
        code = ''.join(random.choices(string.digits, k=6))
        
        # Store in session with timestamp
        print(f"Generated code: {code}")
        
        # Ensure we have a valid session
        if not request.session.session_key:
            request.session.create()
            print(f"Created new session with ID: {request.session.session_key}")
        
        # Generate timestamp and ensure it's an integer
        verification_timestamp = int(time.time())
        
        # Write to session with explicit type conversion
        request.session['verification_code'] = str(code)
        request.session['verification_email'] = str(email).lower()
        request.session['verification_timestamp'] = int(verification_timestamp)
        
        # Clear any previous verification status
        request.session.pop('email_verified', None)
        request.session.pop('verified_email', None)
        
        # Ensure session is marked as modified and save
        request.session.modified = True
        request.session.save()
        
        print("Session data saved successfully")
        
        # SEND THE VERIFICATION EMAIL
        try:
            subject = 'Email Doğrulama Kodu'
            message = f'''
Merhaba,

Email adresinizi doğrulamak için aşağıdaki kodu kullanın:

Doğrulama Kodu: {code}

Bu kod 5 dakika geçerlidir.

Eğer bu talebi siz yapmadıysanız, bu emaili görmezden gelebilirsiniz.

Teşekkürler!
            '''.strip()
            
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [email]
            
            print(f"Attempting to send email to: {email}")
            print(f"From: {from_email}")
            print(f"Subject: {subject}")
            
            # Send the email
            result = send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False,
            )
            
            print(f"Email sent successfully! Result: {result}")
            
        except Exception as email_error:
            print(f"Failed to send email: {str(email_error)}")
            import traceback
            traceback.print_exc()
            
            # Clear session data since email failed
            request.session.pop('verification_code', None)
            request.session.pop('verification_email', None)
            request.session.pop('verification_timestamp', None)
            request.session.save()
            
            return JsonResponse({
                'success': False,
                'error': 'E-posta gönderilemedi. Lütfen e-posta adresinizi kontrol edin ve tekrar deneyin.',
                'details': str(email_error) if settings.DEBUG else None
            })
        
        # Create response with cookies as fallback
        max_age = 300  # 5 minutes in seconds
        response = JsonResponse({
            'success': True, 
            'message': 'Doğrulama kodu e-posta adresinize gönderildi.'
        })
        
        # Set secure cookies as fallback
        cookie_options = {
            'max_age': max_age,
            'httponly': True,
            'samesite': 'Lax',
            'secure': not settings.DEBUG,
            'path': '/',
            'domain': settings.SESSION_COOKIE_DOMAIN or None
        }
        
        response.set_cookie('verification_code', value=code, **cookie_options)
        response.set_cookie('verification_email', value=email, **cookie_options)
        response.set_cookie('verification_timestamp', 
                          value=str(verification_timestamp), 
                          **cookie_options)
        
        print("Response created with cookies")
        return response
        
    except Exception as e:
        error_msg = f'Doğrulama kodu gönderilirken bir hata oluştu: {str(e)}'
        print(error_msg)
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False, 
            'error': 'Doğrulama kodu gönderilemedi. Lütfen tekrar deneyin.'
        })

@csrf_exempt
@require_http_methods(["POST"])
def verify_email_code(request):
    try:
        print("\n=== VERIFY EMAIL CODE ===")
        print(f"Session ID doğrulama sırasında: {request.session.session_key}")
        print(f"Sunucudaki kod: {request.session.get('verification_code')}")
        print(f"Session data: {request.session.items()}")        
        
        # Ensure session is created if it doesn't exist
        if not request.session.session_key:
            request.session.create()
            print(f"Created new session with ID: {request.session.session_key}")
            
        # Parse JSON data from request body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            print("Invalid JSON data received")
            return JsonResponse({'success': False, 'error': 'Geçersiz veri formatı'})
            
        email = data.get('email')
        code = data.get('code')
        print(f"Email: {email}, Gönderilen kod: {code}")
        
        # Check if email is already verified
        email_verified = request.session.get('email_verified', False)
        verified_email = request.session.get('verified_email', '')
        
        if email_verified and verified_email and verified_email.lower() == email.lower():
            print(f"Email {email} is already verified")
            return JsonResponse({'success': True, 'already_verified': True})
        
        # Debug: Print complete session data
        print("\n=== SESSION DATA AT VERIFICATION START ===")
        print(f"Session ID: {request.session.session_key}")
        print(f"Session modified: {request.session.modified}")
        print("Session content:")
        for key, value in request.session.items():
            print(f"  {key}: {value} (type: {type(value)})")
        
        # Get session data with debug info
        session_email = request.session.get('verification_email')
        session_code = request.session.get('verification_code')
        session_timestamp = request.session.get('verification_timestamp')
        
        print("\n=== VERIFICATION DATA ===")
        print(f"Session email: {session_email}")
        print(f"Session code: {session_code}")
        print(f"Session timestamp: {session_timestamp} (type: {type(session_timestamp) if session_timestamp is not None else 'None'})")
        
        # If session data is missing, try to recover from cookies
        if not all([session_code, session_email]):
            print("\n=== ATTEMPTING COOKIE RECOVERY ===")
            cookies_recovered = False
            
            if not session_code and 'verification_code' in request.COOKIES:
                session_code = str(request.COOKIES.get('verification_code'))
                request.session['verification_code'] = session_code
                print(f"Recovered code from cookies: {session_code}")
                cookies_recovered = True
                
            if not session_email and 'verification_email' in request.COOKIES:
                session_email = str(request.COOKIES.get('verification_email')).lower()
                request.session['verification_email'] = session_email
                print(f"Recovered email from cookies: {session_email}")
                cookies_recovered = True
            
            # Set a default timestamp if missing
            if not session_timestamp:
                session_timestamp = int(time.time())
                request.session['verification_timestamp'] = session_timestamp
                print(f"Created new timestamp: {session_timestamp}")
                cookies_recovered = True
            
            # Save session if we recovered any data from cookies
            if cookies_recovered:
                print("Saving recovered data to session...")
                request.session.modified = True
                request.session.save()
                
                # Verify the data was saved
                print("\n=== VERIFYING SESSION AFTER COOKIE RECOVERY ===")
                print(f"Session code: {request.session.get('verification_code')}")
                print(f"Session email: {request.session.get('verification_email')}")
                print(f"Session timestamp: {request.session.get('verification_timestamp')}")
        else:
            print("All session data present, no need to recover from cookies")
        
        # Validate input
        if not email or not code:
            return JsonResponse({'success': False, 'error': 'E-posta ve doğrulama kodu gerekli'})
        
        # Check if session data exists and is valid
        if not all([session_code, session_email]):
            print("Session data is missing or incomplete")
            return JsonResponse({
                'success': False,
                'error': 'Doğrulama kodu bulunamadı veya süresi dolmuş. Lütfen yeni kod talep edin.',
                'code_expired': True
            })
            
        # Validate timestamp type and format
        if session_timestamp is None:
            # If timestamp is missing, create one now
            session_timestamp = int(time.time())
            request.session['verification_timestamp'] = session_timestamp
            request.session.modified = True
            print(f"Created missing timestamp: {session_timestamp}")
        elif not isinstance(session_timestamp, (int, float)):
            print(f"Invalid timestamp type: {type(session_timestamp)}")
            # Convert to int if possible, otherwise create new timestamp
            try:
                session_timestamp = int(float(session_timestamp))
                request.session['verification_timestamp'] = session_timestamp
                request.session.modified = True
                print(f"Converted timestamp to int: {session_timestamp}")
            except (ValueError, TypeError):
                session_timestamp = int(time.time())
                request.session['verification_timestamp'] = session_timestamp
                request.session.modified = True
                print(f"Replaced invalid timestamp with new one: {session_timestamp}")
        
        # Check if code is expired (5 minutes)
        try:
            print("\n=== VALIDATING TIMESTAMP ===")
            print(f"Raw timestamp from session: {session_timestamp} (type: {type(session_timestamp)})")
            
            # Ensure timestamp is an integer
            try:
                timestamp = int(float(session_timestamp)) if str(session_timestamp).strip() else 0
                print(f"Validated timestamp: {timestamp}")
            except (ValueError, TypeError) as e:
                error_msg = f"Invalid timestamp format: {session_timestamp} - {str(e)}"
                print(error_msg)
                return JsonResponse({
                    'success': False,
                    'error': 'Geçersiz zaman damgası formatı',
                    'details': error_msg,
                    'code_expired': True
                })
            
            current_time = int(time.time())
            code_age = current_time - timestamp
            code_timeout = 300  # 5 minutes in seconds
            
            print(f"Current time: {current_time}")
            print(f"Code timestamp: {timestamp}")
            print(f"Code age: {code_age} seconds (max {code_timeout} allowed)")
            
            # Check for negative age (clock skew or timezone issues)
            if code_age < 0:
                print(f"WARNING: Negative code age detected: {code_age} seconds. Possible clock skew or timezone issue.")
            
            if code_age > code_timeout:
                print("Verification code expired")
                
                # Debug: Print session before cleanup
                print("\n=== SESSION BEFORE CLEANUP ===")
                for key, value in request.session.items():
                    print(f"{key}: {value} (type: {type(value)})")
                
                # Clear expired session data
                request.session.pop('verification_code', None)
                request.session.pop('verification_email', None)
                request.session.pop('verification_timestamp', None)
                request.session.save()
                
                # Debug: Print session after cleanup
                print("\n=== SESSION AFTER CLEANUP ===")
                for key, value in request.session.items():
                    print(f"{key}: {value} (type: {type(value)})")
                
                # Clear cookies as well
                response = JsonResponse({
                    'success': False, 
                    'error': 'Doğrulama kodu süresi dolmuş. Lütfen yeni kod talep edin.',
                    'code_expired': True,
                    'details': {
                        'code_age': code_age,
                        'max_age': code_timeout,
                        'current_time': current_time,
                        'code_timestamp': timestamp
                    }
                })
                
                # Delete cookies
                for cookie in ['verification_code', 'verification_email', 'verification_timestamp']:
                    response.delete_cookie(
                        cookie,
                        path='/',
                        domain=settings.SESSION_COOKIE_DOMAIN or None,
                        samesite='Lax'
                    )
                
                return response
                
            print("Code is still valid")
            
        except Exception as e:
            print(f"Error validating code: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Doğrulama kodu kontrol edilirken bir hata oluştu.',
                'details': str(e)
            })
                
        except (ValueError, TypeError) as e:
            print(f"Invalid timestamp format: {session_timestamp}")
            return JsonResponse({
                'success': False,
                'error': 'Geçersiz doğrulama verisi. Lütfen yeni kod talep edin.'
            })
        
        # Verify email matches
        if email.lower() != session_email.lower():
            print(f"Email mismatch: {email} != {session_email}")
            return JsonResponse({
                'success': False, 
                'error': 'E-posta adresi doğrulanamadı. Lütfen tekrar deneyin.'
            })
            
        # Verify code matches
        if code != session_code:
            print(f"Code mismatch: {code} != {session_code}")
            return JsonResponse({
                'success': False, 
                'error': 'Doğrulama kodu yanlış. Lütfen tekrar deneyin.'
            })
        
        # Mark email as verified in session
        request.session['email_verified'] = True
        request.session['verified_email'] = email.lower()
        
        # Clear verification data from session but keep the email
        # This allows for multiple verification attempts with new codes
        request.session.pop('verification_code', None)
        request.session.pop('verification_timestamp', None)
        
        # Save the session to ensure changes are persisted
        request.session.save()
        
        print("Email verified successfully")
        return JsonResponse({'success': True})
        
    except Exception as e:
        print(f"Error in verify_email_code: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False, 
            'error': 'Bir hata oluştu. Lütfen tekrar deneyin.'
        })

def login_and_register(request):
    print("\n=== LOGIN_AND_REGISTER VIEW ===")
    print(f"Session ID: {request.session.session_key}")
    print(f"Session data: {dict(request.session.items())}")
    print(f"Request method: {request.method}")
    print(f"Headers: {dict(request.headers)}")

    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest'
    login_form = LoginForm()
    register_form = CustomUserRegistrationForm()
    # Get all schools and sort them using the Turkish sorting function
    schools = list(School.objects.all())
    schools.sort(key=lambda x: turkish_sort_key(x.name))
    graduation_years = GraduationYear.objects.all()

    if request.method == 'POST':
        print(f"POST request received. AJAX: {is_ajax}")
        print(f"POST data: {request.POST}")

        if 'login_submit' in request.POST:
            login_form = LoginForm(request.POST)
            error_msg = ""
            print("\n=== LOGIN ATTEMPT ===")
            print(f"Form data: {request.POST}")
            print(f"Login form valid: {login_form.is_valid()}")
            print(f"Login form errors: {login_form.errors}")
            
            # Log all form data for debugging
            if login_form.is_valid():
                print("Form is valid, cleaned data:")
                for field, value in login_form.cleaned_data.items():
                    print(f"  {field}: {value}")
            else:
                print("Form validation failed. Errors:")
                for field, errors in login_form.errors.items():
                    print(f"  {field}: {errors}")

            if login_form.is_valid():
                email = login_form.cleaned_data.get("email")
                password = login_form.cleaned_data.get("password")
                
                print("\n=== AUTHENTICATION ATTEMPT ===")
                print(f"Email: {email}")
                print(f"Password: {'*' * len(password) if password else 'Not provided'}")
                
                # Check if user exists with this email
                user_exists = CustomUser.objects.filter(email=email).exists()
                print(f"User with this email exists: {user_exists}")
                
                user = authenticate(request, email=email, password=password)
                print(f"Authentication result: {user}")
                
                if user is not None:
                    print("Authentication successful")
                    print(f"User ID: {user.id}")
                    print(f"User email: {user.email}")
                    print(f"User is active: {user.is_active}")
                    print(f"User last login: {user.last_login}")
                else:
                    print("Authentication failed")
                    if not user_exists:
                        print("No user exists with this email")
                    else:
                        print("Invalid password or user is inactive")

                if user is not None:
                    login(request, user)
                    print("\n=== LOGIN SUCCESSFUL ===")
                    print(f"User {user.email} logged in successfully")
                    print(f"Session key: {request.session.session_key}")
                    print(f"Session data: {dict(request.session.items())}")
                    request.session.modified = True
                    return redirect('school_dashboard')
                else:
                    print("\n=== LOGIN FAILED ===")
                    print("Authentication failed: invalid credentials")
                    print(f"Failed login attempt for email: {email}")
                    print(f"User exists: {user_exists}")
                    messages.error(request, "E-posta veya şifre yanlış.")
            else:
                print("Form is invalid.")
                messages.error(request, "Lütfen formu doğru şekilde doldurun.")

            if is_ajax:
                return JsonResponse({
                    'success': False,
                    'error': error_msg if 'error_msg' in locals() else "Bir hata oluştu."
                }, status=400)
            messages.error(request, error_msg)

        elif is_ajax or 'register_submit' in request.POST:
            print("Processing registration request")
            register_form = CustomUserRegistrationForm(request.POST)

            # Check if email is verified
            verified_email = request.session.get('verified_email', '').lower()
            email_verified = request.session.get('email_verified', False)
            form_email = request.POST.get('email', '').lower()

            print(f"Verified email from session: {verified_email}")
            print(f"Email verified flag: {email_verified}")
            print(f"Email from form: {form_email}")

            if not email_verified or not verified_email or verified_email != form_email:
                error_msg = 'Lütfen e-posta adresinizi doğrulayın. Doğrulama kodu göndermek için e-posta alanına dokunup çıkın.'
                messages.error(request, error_msg)
                print(f"Email not verified or mismatch. Verified: {verified_email}, Form: {form_email}")

                # Return JSON response for AJAX requests
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False,
                        'error': error_msg,
                        'field_errors': {'email': error_msg}
                    }, status=400)

                return redirect('login_register')

            # Validate graduation year
            graduation_year_id = request.POST.get('graduation_year')
            print(f"Graduation year ID from form: {graduation_year_id}")

            if not graduation_year_id:
                error_msg = 'Lütfen mezuniyet yılını seçiniz'
                print(f"Graduation year validation failed: {error_msg}")
                if is_ajax:
                    return JsonResponse({
                        'success': False,
                        'errors': {'graduation_year': ['Lütfen mezuniyet yılını seçiniz']}
                    }, status=400)
                messages.error(request, 'Lütfen mezuniyet yılını seçiniz')
                return render(request, 'users/login_register.html', context)

            try:
                print(f"Looking up graduation year with ID: {graduation_year_id}")
                graduation_year = GraduationYear.objects.get(id=graduation_year_id)
                print(f"Found graduation year: {graduation_year}")
            except GraduationYear.DoesNotExist:
                error_msg = 'Geçersiz mezuniyet yılı'
                print(f"Graduation year not found: {error_msg}")
                if is_ajax:
                    return JsonResponse({
                        'success': False,
                        'errors': {'graduation_year': ['Geçersiz mezuniyet yılı']}
                    }, status=400)
                messages.error(request, 'Geçersiz mezuniyet yılı')
                return render(request, 'users/login_register.html', context)

            if register_form.is_valid():
                print("\n=== REGISTRATION FORM VALIDATION ===")
                print("Form is valid, processing registration...")
                print(f"Form data: {request.POST}")
                
                try:
                    # Create user instance without saving to DB yet
                    user = register_form.save(commit=False)
                    print(f"\n=== USER CREATION ===")
                    print(f"Created user instance: {user}")
                    print(f"Name: {user.first_name} {user.last_name}")
                    print(f"Email: {user.email}")
                    print(f"Graduation year: {graduation_year}")
                    
                    user.graduation_year = graduation_year

                    # Generate unique username
                    base_username = f"{user.first_name.lower()}.{user.last_name.lower()}".replace(" ", "")
                    username = base_username
                    counter = 1
                    
                    print("\n=== GENERATING USERNAME ===")
                    print(f"Base username: {base_username}")
                    
                    # Find available username
                    while True:
                        try:
                            if not CustomUser.objects.filter(username=username).exists():
                                print(f"Username available: {username}")
                                break
                            print(f"Username {username} already exists, trying next...")
                            username = f"{base_username}{counter}"
                            counter += 1
                        except Exception as e:
                            print(f"Error checking username availability: {str(e)}")
                            username = f"user_{int(time.time())}"  # Fallback username
                            print(f"Using fallback username: {username}")
                            break
                            
                    user.username = username
                    print(f"Final username set to: {username}")
                    
                    # Set email notifications preference
                    user.email_notifications_enabled = True
                    print(f"Email notifications enabled: {user.email_notifications_enabled}")

                    # Handle school selection
                    school_value = request.POST.get('school')
                    print("\n=== SCHOOL SELECTION ===")
                    print(f"Selected school value: {school_value}")

                    if school_value == 'other':
                        custom_school_name = request.POST.get('custom_school', '').strip()
                        print(f"Custom school name: {custom_school_name}")
                        
                        if not custom_school_name:
                            error_msg = 'Lütfen okul ismini giriniz'
                            print(f"Validation error: {error_msg}")
                            if is_ajax:
                                return JsonResponse({
                                    'success': False,
                                    'errors': {'custom_school': [error_msg]}
                                }, status=400)
                            messages.error(request, error_msg)
                            return render(request, 'users/login_register.html', context)

                        # Create new school or get existing one
                        try:
                            school, created = School.objects.get_or_create(
                                name__iexact=custom_school_name,
                                defaults={'name': custom_school_name}
                            )
                            print(f"School {'created' if created else 'retrieved'}: {school.name}")
                            user.school = school
                        except Exception as e:
                            error_msg = f'Okul oluşturulurken hata: {str(e)}'
                            print(f"School creation error: {error_msg}")
                            if is_ajax:
                                return JsonResponse({
                                    'success': False,
                                    'errors': {'custom_school': [error_msg]}
                                }, status=400)
                            messages.error(request, error_msg)
                            return render(request, 'users/login_register.html', context)

                    else:
                        try:
                            school_id = int(school_value)
                            user.school = School.objects.get(id=school_id)
                            print(f"Selected school: {user.school.name} (ID: {school_id})")
                        except (School.DoesNotExist, ValueError, TypeError) as e:
                            error_msg = 'Geçersiz okul seçimi'
                            print(f"Invalid school selection (ID: {school_value}): {str(e)}")
                            if is_ajax:
                                return JsonResponse({
                                    'success': False,
                                    'errors': {'school': [error_msg]}
                                }, status=400)
                            messages.error(request, error_msg)
                            return render(request, 'users/login_register.html', context)

                    # Save user with error handling
                    try:
                        print("\n=== SAVING USER ===")
                        user.save()
                        print(f"User saved successfully with ID: {user.id}")
                        print(f"User details - Email: {user.email}, Username: {user.username}")
                        print(f"School: {user.school.name if user.school else 'None'}, Graduation Year: {user.graduation_year}")
                        
                    except IntegrityError as e:
                        error_msg = str(e).lower()
                        print(f"\n=== INTEGRITY ERROR ===")
                        print(f"Error saving user: {error_msg}")
                        
                        if 'email' in error_msg:
                            error_msg = "Bu e-posta adresi zaten kullanılıyor."
                            error_field = 'email'
                        elif 'username' in error_msg:
                            error_msg = "Bu kullanıcı adı zaten alınmış."
                            error_field = 'username'
                        else:
                            error_msg = "Kayıt sırasında bir hata oluştu."
                            error_field = '__all__'
                            
                        print(f"Returning error: {error_msg}")
                        
                        if is_ajax:
                            return JsonResponse({
                                'success': False,
                                'errors': {error_field: [error_msg]}
                            }, status=400)
                        messages.error(request, error_msg)
                        return render(request, 'users/login_register.html', context)

                    # Clear verification session data after successful registration
                    print("\n=== CLEANING UP SESSION ===")
                    for key in ['verification_code', 'verification_email', 'verification_timestamp', 
                               'email_verified', 'verified_email']:
                        if key in request.session:
                            request.session.pop(key)
                            print(f"Removed from session: {key}")
                    
                    # Log the user in
                    print("\n=== LOGGING IN USER ===")
                    login(request, user)
                    print(f"User {user.email} logged in successfully")
                    print(f"Session key: {request.session.session_key}")
                    
                    # Prepare success response
                    response_data = {
                        'success': True,
                        'redirect_url': reverse('school_dashboard'),
                        'message': "Kayıt başarılı!"
                    }
                    print(f"Registration successful, redirecting to: {response_data['redirect_url']}")
                    
                    if is_ajax:
                        return JsonResponse(response_data)
                        
                    messages.success(request, "Kayıt başarılı!")
                    return redirect('school_dashboard')

                except IntegrityError as e:
                    error_msg = "Kayıt sırasında bir hata oluştu."
                    field = None
                    e_lower = str(e).lower()
                    if 'email' in e_lower:
                        error_msg = "Bu e-posta adresi zaten kullanılıyor. Lütfen farklı bir e-posta deneyin."
                        field = 'email'
                    elif 'username' in e_lower:
                        error_msg = "Bu kullanıcı adı zaten alınmış. Lütfen ad/soyadınızı değiştirin."
                        field = 'username'

                    if is_ajax:
                        return JsonResponse({
                            'success': False,
                            'error': error_msg,
                            'field_errors': {field: [error_msg]} if field else {}
                        }, status=400)
                    messages.error(request, error_msg)
                except Exception as e:
                    print(f"Error during registration: {str(e)}")
                    error_msg = f"Kayıt sırasında bir hata oluştu: {str(e)}"
                    if is_ajax:
                        return JsonResponse({
                            'success': False,
                            'error': error_msg
                        }, status=400)
                    messages.error(request, error_msg)
            else:
                # Hatalı form durumunda hataları detaylı şekilde dön
                print(f"Registration form errors: {register_form.errors}")
                if is_ajax:
                    errors_dict = {}
                    for field, error_list in register_form.errors.items():
                        errors_dict[field] = [str(error) for error in error_list]

                    return JsonResponse({
                        'success': False,
                        'errors': errors_dict
                    }, status=400)

                for field, errors in register_form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")

    context = {
        'login_form': login_form,
        'register_form': register_form,
        'schools': schools,
        'graduation_years': graduation_years,
    }

    if not is_ajax:
        return render(request, 'users/login_register.html', context)

    # For AJAX requests that aren't handled above
    return JsonResponse({
        'success': False,
        'error': 'Invalid request'
    })


# ----------------------------------------------------------------------
# Django'nun LoginView'ını kullanan Özel Giriş View'u
# ----------------------------------------------------------------------
class CustomLoginView(LoginView):
    template_name = 'users/login.html'

    def get_success_url(self):
        if self.request.session.get("school_id") and self.request.session.get("graduation_year_id"):
            return reverse_lazy('yearbook')
        else:
            return reverse_lazy('school_login')


# ----------------------------------------------------------------------
# Kullanıcı Çıkışı (Logout)
# ----------------------------------------------------------------------
def user_logout(request):
    logout(request)
    return redirect('login_register')


# ----------------------------------------------------------------------
# Okul Giriş View'u: School ve mezuniyet yılına göre giriş kontrolü yapar.
# ----------------------------------------------------------------------
def school_login(request):
    # Kullanıcı oturumunu açmış fakat okul bilgileri zaten kayıtlı ise; yeniden doğrulamaya gerek yok.
    if request.user.is_authenticated and request.user.school:
        return redirect('profile')

    error_message = None

    if request.method == "POST":
        school_id = request.POST.get('school_id')
        graduation_year_val = request.POST.get('graduation_year')
        password = request.POST.get('password')

        try:
            school = School.objects.get(id=school_id)
            year_obj = GraduationYear.objects.get(school=school, year=graduation_year_val)
            if check_password(password, year_obj.password):
                # Doğrulama başarılı; kullanıcı modeline okul bilgilerini kaydediyoruz.
                user = request.user
                user.school = school
                user.graduation_year = year_obj
                user.save()
                request.session['school_id'] = school.id
                request.session['graduation_year_id'] = year_obj.id
                # Başarılı doğrulama sonrası school_dashboard sayfasına yönlendiriyoruz.
                return redirect('school_dashboard')
            else:
                error_message = 'Yanlış şifre!'
        except School.DoesNotExist:
            error_message = 'Okul bulunamadı!'
        except GraduationYear.DoesNotExist:
            error_message = 'Mezuniyet yılı bulunamadı!'

    schools = School.objects.all()
    years = GraduationYear.objects.values('school', 'year')
    years_json = json.dumps(list(years))

    context = {
        'schools': schools,
        'years_json': years_json,
        'error_message': error_message,
    }
    return render(request, 'users/school_login.html', context)

# ----------------------------------------------------------------------
# Yıllık (Yearbook) View: Oturumdan alınan school_id ve graduation_year_id ile
# aynı okul ve mezuniyet yılına sahip öğrencileri listeler.
# ----------------------------------------------------------------------
@login_required
def yearbook(request):
    try:
        if not request.user.school or not request.user.graduation_year:
            messages.warning(request, 'Lütfen önce profil sayfanızdan okul ve mezuniyet yılı bilgilerinizi ayarlayın.')
            return redirect('profile')

        # Get all students from the same school and year
        students = CustomUser.objects.filter(
            school=request.user.school,
            graduation_year=request.user.graduation_year
        ).order_by('first_name', 'last_name')

        # Get messages for the current user
        user_messages = Message.objects.filter(receiver=request.user).order_by('-created_at')

        # Get current student index and calculate prev/next
        current_student = request.user
        student_list = list(students)
        current_index = student_list.index(current_student)
        prev_student = student_list[current_index - 1] if current_index > 0 else None
        next_student = student_list[current_index + 1] if current_index < len(student_list) - 1 else None

        # Handle AJAX requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            page_type = request.GET.get('page', 'current')
            target_student = None
            
            if page_type == 'next' and next_student:
                target_student = next_student
            elif page_type == 'prev' and prev_student:
                target_student = prev_student
            
            if target_student:
                context = {
                    'user': target_student,
                    'school': target_student.school,
                    'graduation_year': target_student.graduation_year,
                    'has_prev': student_list.index(target_student) > 0,
                    'has_next': student_list.index(target_student) < len(student_list) - 1
                }
                return render(request, "users/yearbook_content.html", context)
            
            return JsonResponse({'error': 'No more pages'}, status=404)

        context = {
            'user': current_student,
            'school': request.user.school,
            'graduation_year': request.user.graduation_year,
            'has_prev': current_index > 0,
            'has_next': current_index < len(student_list) - 1,
            'messages': user_messages  # Add messages to context
        }
        return render(request, "users/yearbook.html", context)
    except Exception as e:
        logger.error(f"Error in yearbook view for user {request.user.username}: {str(e)}")
        messages.error(request, 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.')
        return redirect('profile')


# ----------------------------------------------------------------------
# Kullanıcı Profil View'u: Sadece giriş yapmış kullanıcılar erişebilir.
# ----------------------------------------------------------------------
@login_required
def profile(request):
    # Profil sayfasında (pembe tablo) kullanıcıya ait bilgiler ve "Kapak Animasyonu" ile
    # kişisel sayfaya geçiş seçeneği bulunur.
    return render(request, 'users/profile.html', {'user': request.user})


# ----------------------------------------------------------------------
# Arkadaş Profili Sayfası:
# Arkadaşın profil fotoğrafı, adı-soyadı görüntülenir;
# Kullanıcı not bırakabilir ve başkalarının bıraktığı notlar listelenir.
# ----------------------------------------------------------------------
@login_required
def friend_profile(request, friend_id):
    friend = get_object_or_404(CustomUser, id=friend_id)
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            Message.objects.create(sender=request.user, receiver=friend, content=content)
            Note.objects.create(sender=request.user, receiver=friend, content=content, year=friend.graduation_year.year)
            messages.success(request, "Notunuz gönderildi!")
            return redirect('friend_profile', friend_id=friend.id)
    # Bu arkadaşın üzerine bırakılmış notları listele
    friend_messages = Message.objects.filter(receiver=friend).order_by('-created_at')
    return render(request, 'users/friend_profile.html', {
        'friend': friend,
        'messages': friend_messages,
    })

@login_required
def view_friend(request, friend_id):
    """
    Display a friend's profile with their messages.
    Only shows visible messages to other users.
    """
    profile_user = get_object_or_404(CustomUser, id=friend_id)

    # Start with all messages for the profile user
    friend_messages = Message.objects.filter(receiver=profile_user)

    # If the viewer is not the profile owner, filter for visible messages
    if request.user != profile_user:
        friend_messages = friend_messages.filter(visible=True)

    # Order the final queryset
    friend_messages = friend_messages.order_by('-created_at')

    return render(request, 'users/friends.html', {
        'profile_user': profile_user,
        'messages': friend_messages,
    })


# ----------------------------------------------------------------------
# Mesaj Gönderme: Belirtilen receiver_id'ye mesaj gönderir.
# (Arkadaş Profili üzerinden not bırakma işlemi olduğu için bu view isteğe bağlıdır.)
# ----------------------------------------------------------------------
@login_required
def send_message(request, receiver_id):
    receiver = get_object_or_404(CustomUser, id=receiver_id)

    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            # Create the message
            message = Message.objects.create(sender=request.user, receiver=receiver, content=content)

            # Send email notification if enabled
            if receiver.email_notifications_enabled:
                subject = f'📩 Yeni bir mesajınız var! - {request.user.get_full_name() or request.user.email}'
                message_content = f"""
                Merhaba {receiver.get_full_name() or receiver.username}👋,

                {request.user.get_full_name() or request.user.email} size bir mesaj gönderdi.

                Mesajınızı görmek için aşağıdaki bağlantıya tıklayarak giriş yapabilirsiniz:

                👉 {request.build_absolute_uri(reverse('login_register'))}

                Eğer bu mesajı beklemiyorsanız, bu e-postayı güvenle yok sayabilirsiniz.

                Sevgilerle 😊

                🎓 {request.get_host()}
                """

                try:
                    send_mail(
                        subject=subject,
                        message=message_content.strip(),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[receiver.email],
                        fail_silently=True,
                    )
                except Exception as e:
                    logger.error(f"E-posta gönderilirken hata oluştu: {str(e)}")
            
            messages.success(request, "Mesaj gönderildi!")
            return redirect('school_dashboard')
        else:
            messages.error(request, "Mesaj boş olamaz!")

    return render(request, 'users/send_message.html', {'receiver': receiver})


# ----------------------------------------------------------------------
# Benim Yazdıklarım Sayfası:
# Kullanıcının diğerlerine bıraktığı notları listeler.
# ----------------------------------------------------------------------
@login_required
def my_notes(request):
    notes = Message.objects.filter(sender=request.user).order_by('-created_at')
    return render(request, 'users/my_notes.html', {'notes': notes})


@login_required
@require_POST
def toggle_message_visibility(request, message_id):
    try:
        message = Message.objects.get(id=message_id, receiver=request.user)
    except Message.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Mesaj bulunamadı veya yetkiniz yok.'}, status=404)

    message.visible = not message.visible
    message.save(update_fields=['visible'])

    return JsonResponse({'status': 'success', 'visible': message.visible})


# ----------------------------------------------------------------------
# Mesaj Düzenleme Sayfası:
# Kullanıcının gönderdiği bir mesajı düzenlemesini sağlar.
# ----------------------------------------------------------------------
@login_required
def edit_message(request, message_id):
    # Mesajı getir ve kullanıcının kendi mesajı olduğunu doğrula
    message = get_object_or_404(Message, id=message_id, sender=request.user)
    
    if request.method == 'POST':
        new_content = request.POST.get('content')
        if new_content and new_content.strip():
            message.content = new_content
            message.save()
            messages.success(request, "Mesajınız başarıyla güncellendi.")
            return redirect('my_notes')
        else:
            messages.error(request, "Mesaj içeriği boş olamaz.")
    
    return render(request, 'users/edit_message.html', {'message': message})


# ----------------------------------------------------------------------
# Mesaj Silme İşlevi:
# Kullanıcının gönderdiği bir mesajı silmesini sağlar.
# ----------------------------------------------------------------------
@login_required
def delete_message(request, pk):
    # Mesajı getir ve kullanıcının kendisine gönderilmiş olduğunu doğrula
    message = get_object_or_404(Message, pk=pk, receiver=request.user)

    if request.method in ['POST', 'GET']:
        message.delete()
        messages.success(request, "Mesaj başarıyla silindi.")
        return redirect('yearbook')

    return redirect('yearbook')

@login_required
def delete_sent_message(request, pk):
    # Mesajı getir ve kullanıcının gönderdiği mesaj olduğunu doğrula
    message = get_object_or_404(Message, pk=pk, sender=request.user)

    if request.method in ['POST', 'GET']:
        message.delete()
        messages.success(request, "Mesaj başarıyla silindi.")
        return redirect('my_notes')

    return redirect('my_notes')


# ----------------------------------------------------------------------
# Ayarlar Sayfası:
# "Bana Yazılanlar" gibi gizlilik ayarlarının yapıldığı kısım.
# ----------------------------------------------------------------------
@login_required
def settings_view(request):
    if request.method == "POST":
        # Örneğin, kullanıcı "Bana Yazılanlar" seçeneğini açıp kapatabilir.
        show_inbox = request.POST.get("show_inbox") == "on"
        # CustomUser modeli üzerinde "show_received_messages" diye bir alan varsayalım.
        request.user.show_received_messages = show_inbox
        request.user.save()
        messages.success(request, "Ayarlar güncellendi!")
    return render(request, "users/settings.html", {"user": request.user})


# ----------------------------------------------------------------------
# Geri Bildirim Sayfası:
# Kullanıcıların yilliksite@gmail.com adresine geri bildirim göndermesini sağlar
# ----------------------------------------------------------------------
@login_required
def feedback_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        message_content = request.POST.get('message')
        
        # Form doğrulama
        if not email or not message_content:
            messages.error(request, 'Lütfen tüm alanları doldurun.')
            return render(request, 'users/feedback.html')
            
        # E-posta gönderme
        try:
            subject = 'Yıllık Sitesi Geri Bildirimi'
            message = f"Gönderen: {email}\n\nMesaj:\n{message_content}"
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = ['yilliksite@gmail.com']
            
            send_mail(
                subject,
                message,
                from_email,
                recipient_list,
                fail_silently=False,
            )
            
            messages.success(request, 'Geri bildiriminiz başarıyla gönderildi. Teşekkür ederiz!')
            return redirect('feedback_view')
        except Exception as e:
            messages.error(request, f'Geri bildirim gönderilirken bir hata oluştu: {str(e)}')
    
    return render(request, 'users/feedback.html')


# ----------------------------------------------------------------------
# Kullanıcı Arama View'u: Kullanıcı adı, okul veya mezuniyet yılına göre arama yapar.
# ----------------------------------------------------------------------
def search_users(request):
    form = UserSearchForm(request.GET)
    users = CustomUser.objects.all()

    if form.is_valid():
        if form.cleaned_data['username']:
            users = users.filter(username__icontains=form.cleaned_data['username'])
        if form.cleaned_data['school']:
            users = users.filter(school__name__icontains=form.cleaned_data['school'])
        if form.cleaned_data['year']:
            users = users.filter(school__graduationyear__year=form.cleaned_data['year']).distinct()

    return render(request, 'users/search_results.html', {
        'form': form,
        'users': users,
    })


# ----------------------------------------------------------------------
# Okul Dashboard View'u: Kullanıcının bağlı olduğu okul bilgilerini gösterir.
# ----------------------------------------------------------------------
@login_required
def school_dashboard(request):
    try:
        # Check if user has school and graduation year
        if not request.user.school or not request.user.graduation_year:
            messages.warning(request, 'Lütfen önce profil sayfanızdan okul ve mezuniyet yılı bilgilerinizi ayarlayın.')
            return redirect('profile')

        # Get students from the same school and graduation year
        students = CustomUser.objects.filter(
            school=request.user.school,
            graduation_year=request.user.graduation_year
        ).exclude(id=request.user.id).order_by('first_name', 'last_name')

        context = {
            'school': request.user.school,
            'graduation_year': request.user.graduation_year,
            'students': students,
        }
        return render(request, 'users/school_dashboard.html', context)
    except Exception as e:
        logger.error(f"Error in school_dashboard for user {request.user.username}: {str(e)}")
        messages.error(request, 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.')
        return redirect('profile')

# ----------------------------------------------------------------------
# Standart Giriş View'u (Klasik Form ile)
# ----------------------------------------------------------------------
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user:
                login(request, user)
                if request.session.get("school_id") and request.session.get("graduation_year_id"):
                    return redirect('yearbook')
                else:
                    return redirect('school_login')
            else:
                messages.error(request, "Giriş başarısız. Lütfen bilgilerinizi kontrol edin.")
        else:
            messages.error(request, "Giriş başarısız. Lütfen bilgilerinizi kontrol edin.")
    else:
        form = LoginForm()
    return render(request, 'users/login.html', {'form': form})


# ----------------------------------------------------------------------
# Başarılı Giriş Sayfası
# ----------------------------------------------------------------------
def success_page(request):
    return render(request, 'users/success.html')

@login_required
def download_user_data(request):
    # Kullanıcı verilerini topla
    user = request.user
    data = {
        'profile': {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'department': user.department,
            'school': user.school.name if user.school else None,
            'graduation_year': user.graduation_year.year if user.graduation_year else None,
            'date_joined': user.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None,
        },
        'messages_sent': [
            {
                'id': message.id,
                'receiver': message.receiver.get_full_name(),
                'content': message.content,
                'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for message in Message.objects.filter(sender=user)
        ],
        'messages_received': [
            {
                'id': message.id,
                'sender': message.sender.get_full_name(),
                'content': message.content,
                'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for message in Message.objects.filter(receiver=user)
        ],
        'notes_sent': [
            {
                'id': note.id,
                'receiver': note.receiver.get_full_name(),
                'content': note.content,
                'year': note.year,
                'created_at': note.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for note in Note.objects.filter(sender=user)
        ],
        'notes_received': [
            {
                'id': note.id,
                'sender': note.sender.get_full_name(),
                'content': note.content,
                'year': note.year,
                'created_at': note.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for note in Note.objects.filter(receiver=user)
        ]
    }
    
    # JSON dosyası olarak indir
    response = JsonResponse(data, json_dumps_params={'ensure_ascii': False, 'indent': 4})
    response['Content-Disposition'] = f'attachment; filename="{user.username}_data.json"'
    return response


@require_http_methods(["POST"])
def send_verification_code(request):
    try:
        print("Received verification code request")
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            print("No email provided")
            return JsonResponse({'success': False, 'error': 'E-posta adresi gerekli'})
        
        # Generate a 6-digit verification code
        code = ''.join(random.choices(string.digits, k=6))
        print(f"Generated verification code for email: {email}")
        
        # Store the code in session
        request.session['verification_code'] = code
        request.session['verification_email'] = email
        
        try:
            # Send the verification email
            print(f"Attempting to send email to {email}")
            send_mail(
                    'E-posta Doğrulama Kodu',
                    f'''
                    
                Doğrulama kodunuz: {code}

                Bu kod 10 dakika boyunca geçerlidir.

                İyi günler dileriz! 😊
                ''',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
            print("Email sent successfully")
            
            return JsonResponse({'success': True, 'code': code})
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return JsonResponse({
                'success': False, 
                'error': 'E-posta gönderilemedi. Lütfen e-posta ayarlarınızı kontrol edin.'
            })
        
    except json.JSONDecodeError:
        print("Invalid JSON data received")
        return JsonResponse({'success': False, 'error': 'Geçersiz veri formatı'})
    except Exception as e:
        print(f"Unexpected error in send_verification_code: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)})

@require_http_methods(["GET"])
def get_graduation_years(request):
    try:
        # Get all graduation years
        graduation_years = GraduationYear.objects.all().order_by('-year').values('id', 'year')
        
        # Log the request for debugging
        logger.info(f"Fetching graduation years. Request: {request.GET}")
        logger.info(f"Found {len(graduation_years)} graduation years")
        
        return JsonResponse({
            'graduation_years': list(graduation_years)
        })
    except Exception as e:
        logger.error(f"Error in get_graduation_years: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
import logging

logger = logging.getLogger(__name__)


@login_required
def profile_view(request):
    try:
        user = request.user
        has_photo = user.profile_photo and user.profile_photo.name
        photo_url = None

        if has_photo:
            try:
                photo_url = user.profile_photo.url
            except ValueError:
                has_photo = False
                logger.warning(f"Photo file not found for user {user.username}: {user.profile_photo.name}")

        context = {
            'user': user,
            'has_photo': has_photo,
            'photo_url': photo_url,
            'department': getattr(user, 'department', None),
            'sent_messages_count': user.sent_messages.count(),
            'received_messages_count': user.received_messages.count(),
        }
        return render(request, 'users/profile.html', context)
    except Exception as e:
        logger.error(f"Error in profile_view: {str(e)}")
        return render(request, 'users/profile.html', {
            'user': request.user,
            'has_photo': False,
            'photo_url': None,
            'department': None,
            'sent_messages_count': 0,
            'sent_notes_count': 0  # Add fallback
        })

@login_required
@require_POST
def update_profile_photo(request):
    if 'photo' not in request.FILES:
        return JsonResponse({'success': False, 'error': 'No photo provided'})
    
    photo = request.FILES['photo']
    
    # Validate file type
    if not photo.content_type.startswith('image/'):
        return JsonResponse({'success': False, 'error': 'Geçersiz dosya türü. Lütfen bir resim dosyası yükleyin.'})
    
    # Validate file size (max 5MB)
    if photo.size > 5 * 1024 * 1024:
        return JsonResponse({'success': False, 'error': 'Dosya boyutu çok büyük (maksimum 5MB)'})
    
    try:
        # Delete old photo if exists
        if request.user.profile_photo:
            request.user.profile_photo.delete()
        
        request.user.profile_photo = photo
        request.user.save()
        
        return JsonResponse({'success': True, 'url': request.user.profile_photo.url})
    except Exception as e:
        logger.error(f"Error updating profile photo: {str(e)}")
        return JsonResponse({'success': False, 'error': 'Fotoğraf güncellenirken bir hata oluştu'})

@login_required
@require_POST
def update_graduation_photo(request):
    logger.info("update_graduation_photo view called")
    
    if 'graduation_photo' not in request.FILES:
        logger.error("No graduation_photo in request.FILES")
        return JsonResponse({'success': False, 'error': 'Lütfen bir fotoğraf seçin'})
    
    photo = request.FILES['graduation_photo']
    logger.info(f"Received file: {photo.name}, size: {photo.size}, type: {photo.content_type}")
    
    # Validate file type
    if not photo.content_type.startswith('image/'):
        logger.error(f"Invalid file type: {photo.content_type}")
        return JsonResponse({'success': False, 'error': 'Geçersiz dosya türü. Lütfen bir resim dosyası yükleyin.'})
    
    # Validate file size (max 5MB)
    if photo.size > 5 * 1024 * 1024:
        logger.error(f"File too large: {photo.size} bytes")
        return JsonResponse({'success': False, 'error': 'Dosya boyutu çok büyük (maksimum 5MB)'})
    
    try:
        # Check if user has graduation_photo field
        if not hasattr(request.user, 'graduation_photo'):
            logger.error("User model does not have graduation_photo field")
            return JsonResponse({
                'success': False, 
                'error': 'Kullanıcı modelinde mezuniyet fotoğrafı alanı bulunamadı. Lütfen yöneticiye başvurun.'
            })
        
        logger.info(f"User has graduation_photo field: {bool(request.user.graduation_photo)}")
        
        # Delete old graduation photo if exists
        if request.user.graduation_photo:
            try:
                logger.info(f"Deleting old graduation photo: {request.user.graduation_photo}")
                request.user.graduation_photo.delete(save=False)
            except Exception as e:
                logger.error(f"Error deleting old graduation photo: {str(e)}")
        
        # Save new graduation photo
        logger.info("Saving new graduation photo")
        request.user.graduation_photo = photo
        request.user.save()
        
        # Get the URL of the saved photo
        photo_url = request.user.graduation_photo.url
        logger.info(f"Photo saved successfully. URL: {photo_url}")
        
        return JsonResponse({
            'success': True, 
            'url': photo_url,
            'message': 'Mezuniyet fotoğrafı başarıyla güncellendi'
        })
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in update_graduation_photo: {error_msg}", exc_info=True)
        return JsonResponse({
            'success': False, 
            'error': f'Mezuniyet fotoğrafı güncellenirken bir hata oluştu: {error_msg}'
        })

@require_POST
@login_required
@require_POST
def update_notes_graduation_photo(request):
    logger.info("update_notes_graduation_photo view called")
    
    if 'graduation_photo' not in request.FILES:
        logger.error("No graduation_photo in request.FILES")
        return JsonResponse({'success': False, 'error': 'Lütfen bir fotoğraf seçin'})
    
    photo = request.FILES['graduation_photo']
    logger.info(f"Received file: {photo.name}, size: {photo.size}, type: {photo.content_type}")
    
    # Validate file type
    if not photo.content_type.startswith('image/'):
        logger.error(f"Invalid file type: {photo.content_type}")
        return JsonResponse({'success': False, 'error': 'Geçersiz dosya türü. Lütfen bir resim dosyası yükleyin.'})
    
    # Validate file size (max 5MB)
    if photo.size > 5 * 1024 * 1024:
        logger.error(f"File too large: {photo.size} bytes")
        return JsonResponse({'success': False, 'error': 'Dosya boyutu çok büyük (maksimum 5MB)'})
    
    try:
        # Check if user has notes_graduation_photo field
        if not hasattr(request.user, 'notes_graduation_photo'):
            logger.error("User model does not have notes_graduation_photo field")
            return JsonResponse({
                'success': False, 
                'error': 'Kullanıcı modelinde notlar sayfası mezuniyet fotoğrafı alanı bulunamadı. Lütfen yöneticiye başvurun.'
            })
        
        logger.info(f"User has notes_graduation_photo field: {bool(request.user.notes_graduation_photo)}")
        
        # Delete old notes_graduation_photo if exists
        if request.user.notes_graduation_photo:
            try:
                logger.info(f"Deleting old notes graduation photo: {request.user.notes_graduation_photo}")
                request.user.notes_graduation_photo.delete(save=False)
            except Exception as e:
                logger.error(f"Error deleting old notes graduation photo: {str(e)}")
        
        # Save new notes_graduation_photo
        logger.info("Saving new notes graduation photo")
        request.user.notes_graduation_photo = photo
        request.user.save()
        
        # Get the URL of the saved photo
        photo_url = request.user.notes_graduation_photo.url
        logger.info(f"Notes photo saved successfully. URL: {photo_url}")
        
        return JsonResponse({
            'success': True, 
            'url': photo_url,
            'message': 'Notlar sayfası mezuniyet fotoğrafı başarıyla güncellendi'
        })
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in update_notes_graduation_photo: {error_msg}", exc_info=True)
        return JsonResponse({
            'success': False, 
            'error': f'Notlar sayfası mezuniyet fotoğrafı güncellenirken bir hata oluştu: {error_msg}'
        })

def update_personal_info(request):
    try:
        data = json.loads(request.body)
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        department = data.get('department')
        
        # Handle department update if only department is being updated
        if department is not None and first_name is None and last_name is None:
            if request.user.has_edited_department:
                return JsonResponse({'success': False, 'error': 'Bölüm bilgisi sadece bir kez düzenlenebilir'})
            
            request.user.department = department
            request.user.has_edited_department = True
            request.user.save()
            return JsonResponse({'success': True, 'message': 'Bölüm bilgisi başarıyla güncellendi'})
        
        # Handle name update if name fields are being updated
        if first_name is not None or last_name is not None:
            if not first_name or not last_name:
                return JsonResponse({'success': False, 'error': 'Ad ve soyad alanları zorunludur'})
            
            # Check if user has already edited their name
            if request.user.has_edited_name:
                return JsonResponse({'success': False, 'error': 'İsim ve soyisim sadece bir kez düzenlenebilir'})
            
            # Update username based on first and last name
            new_username = f"{first_name.lower()}.{last_name.lower()}"
            
            # Check if username already exists
            if CustomUser.objects.filter(username=new_username).exclude(id=request.user.id).exists():
                counter = 1
                while CustomUser.objects.filter(username=f"{new_username}{counter}").exists():
                    counter += 1
                new_username = f"{new_username}{counter}"
            
            # Only update name-related fields
            request.user.first_name = first_name
            request.user.last_name = last_name
            request.user.username = new_username
            request.user.has_edited_name = True
            request.user.last_name_edit_date = timezone.now()
            request.user.save()
            return JsonResponse({'success': True, 'message': 'İsim bilgileri başarıyla güncellendi'})
        
        return JsonResponse({'success': False, 'error': 'Güncellenecek geçerli bir alan belirtilmedi'})
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Geçersiz veri formatı'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

class UnifiedPasswordResetView(PasswordResetView):
    template_name = 'users/password_reset_unified.html'
    email_template_name = 'reset_email.html'
    subject_template_name = 'reset_subject.txt'
    success_url = '/password_reset/done/'
    extra_context = {'current_step': 'form'}
    
    def form_valid(self, form):
        email = form.cleaned_data["email"]
        users = list(form.get_users(email))
        if not users:
            logger.warning(f"[Şifre Sıfırlama] Geçerli bir kullanıcı bulunamadı: {email}")
        else:
            logger.info(f"[Şifre Sıfırlama] E-posta gönderilecek: {email}")
        return super().form_valid(form)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['domain'] = getattr(settings, 'DEFAULT_DOMAIN', '127.0.0.1:8000')
        context['protocol'] = 'https' if self.request.is_secure() else 'http'
        return context


class UnifiedPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'users/password_reset_unified.html'
    extra_context = {'current_step': 'done'}


class UnifiedPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'users/password_reset_unified.html'
    success_url = '/reset/done/'
    extra_context = {'current_step': 'confirm'}


class UnifiedPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'users/password_reset_unified.html'
    extra_context = {'current_step': 'complete'}


@login_required
@require_http_methods(["POST"])
def update_email_notifications(request):
    """
    Update user's email notification preference via AJAX
    """
    try:
        data = json.loads(request.body)
        enabled = data.get('enabled', False)
        request.user.email_notifications_enabled = enabled
        request.user.save()
        return JsonResponse({'status': 'success', 'message': 'E-posta bildirim ayarları güncellendi.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


def cleanup_photo(request):
    try:
        user = request.user
        if user.profile_photo:
            # Get both the storage path and filesystem path
            storage_path = user.profile_photo.name
            fs_path = user.profile_photo.path
            
            # First check if file exists in storage
            try:
                if not default_storage.exists(storage_path):
                    logger.info(f"Photo not found in storage for user {user.username}: {storage_path}")
                    user.profile_photo.delete(save=False)
                    user.profile_photo = None
                    user.save()
                    return JsonResponse({
                        'success': True,
                        'message': 'Invalid photo reference cleaned up',
                        'details': {
                            'storage_path': storage_path,
                            'filesystem_path': fs_path,
                            'user': user.username,
                            'action': 'removed_missing_photo',
                            'reason': 'file_not_found_in_storage'
                        }
                    })
            except SuspiciousFileOperation as e:
                logger.error(f"Suspicious file operation for user {user.username}: {str(e)}")
                user.profile_photo.delete(save=False)
                user.profile_photo = None
                user.save()
                return JsonResponse({
                    'success': True,
                    'message': 'Invalid photo reference cleaned up',
                    'details': {
                        'storage_path': storage_path,
                        'filesystem_path': fs_path,
                        'user': user.username,
                        'action': 'removed_missing_photo',
                        'reason': 'suspicious_file_operation',
                        'error': str(e)
                    }
                })
            
            # If file exists in storage, verify it's actually accessible
            try:
                # Try to open and read a small portion of the file
                with default_storage.open(storage_path) as f:
                    f.read(1)
                
                # Also verify the file exists in the filesystem
                if not os.path.exists(fs_path):
                    logger.warning(f"Photo exists in storage but not in filesystem for user {user.username}: {fs_path}")
                    user.profile_photo.delete(save=False)
                    user.profile_photo = None
                    user.save()
                    return JsonResponse({
                        'success': True,
                        'message': 'Invalid photo reference cleaned up',
                        'details': {
                            'storage_path': storage_path,
                            'filesystem_path': fs_path,
                            'user': user.username,
                            'action': 'removed_missing_photo',
                            'reason': 'file_missing_in_filesystem'
                        }
                    })
                
                # Verify the file is accessible via HTTP
                try:
                    photo_url = urljoin(settings.MEDIA_URL, storage_path)
                    absolute_url = request.build_absolute_uri(photo_url)
                    response = requests.head(absolute_url, timeout=5)
                    
                    if response.status_code != 200:
                        logger.warning(f"Photo not accessible via HTTP for user {user.username}: {absolute_url} (Status: {response.status_code})")
                        user.profile_photo.delete(save=False)
                        user.profile_photo = None
                        user.save()
                        return JsonResponse({
                            'success': True,
                            'message': 'Invalid photo reference cleaned up',
                            'details': {
                                'storage_path': storage_path,
                                'filesystem_path': fs_path,
                                'http_url': absolute_url,
                                'http_status': response.status_code,
                                'user': user.username,
                                'action': 'removed_missing_photo',
                                'reason': 'file_not_accessible_via_http'
                            }
                        })
                except requests.RequestException as e:
                    logger.error(f"Error checking HTTP access for photo: {str(e)}")
                    user.profile_photo.delete(save=False)
                    user.profile_photo = None
                    user.save()
                    return JsonResponse({
                        'success': True,
                        'message': 'Invalid photo reference cleaned up',
                        'details': {
                            'storage_path': storage_path,
                            'filesystem_path': fs_path,
                            'user': user.username,
                            'action': 'removed_missing_photo',
                            'reason': 'http_check_failed',
                            'error': str(e)
                        }
                    })
                
                # If we get here, the file exists and is accessible
                return JsonResponse({
                    'success': True,
                    'message': 'Photo exists and is accessible',
                    'details': {
                        'storage_path': storage_path,
                        'filesystem_path': fs_path,
                        'http_url': absolute_url,
                        'user': user.username,
                        'action': 'no_action_needed',
                        'reason': 'file_exists_and_accessible'
                    }
                })
                
            except Exception as e:
                logger.error(f"Error accessing photo for user {user.username}: {str(e)}")
                user.profile_photo.delete(save=False)
                user.profile_photo = None
                user.save()
                return JsonResponse({
                    'success': True,
                    'message': 'Invalid photo reference cleaned up',
                    'details': {
                        'storage_path': storage_path,
                        'filesystem_path': fs_path,
                        'user': user.username,
                        'action': 'removed_missing_photo',
                        'reason': 'file_access_error',
                        'error': str(e)
                    }
                })
        else:
            return JsonResponse({
                'success': True,
                'message': 'No photo reference to clean up',
                'details': {
                    'user': user.username,
                    'action': 'no_photo_reference',
                    'reason': 'no_photo_field'
                }
            })
    except Exception as e:
        logger.error(f"Error cleaning up photo for user {request.user.username}: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e),
            'details': {
                'user': request.user.username,
                'action': 'error_occurred',
                'reason': 'unexpected_error'
            }
        }, status=500)
