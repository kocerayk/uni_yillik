import resend
import logging
from django.conf import settings

logger = logging.getLogger('email_debug')

def send_verification_email(email, code):
    """
    Resend API kullanarak doğrulama e-postası gönderir
    """
    try:
        # Resend API key'i ayarla
        resend.api_key = settings.RESEND_API_KEY
        
        # E-posta içeriği
        subject = "Email Doğrulama Kodu - Yıllık Site"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Email Doğrulama</title>
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px; text-align: center;">
                <h1 style="color: #333; margin-bottom: 20px;">Email Doğrulama</h1>
                <p style="color: #666; font-size: 16px; margin-bottom: 30px;">
                    Hesabınızı oluşturmak için aşağıdaki doğrulama kodunu kullanın:
                </p>
                <div style="background-color: #007bff; color: white; font-size: 32px; font-weight: bold; 
                           padding: 20px; border-radius: 8px; letter-spacing: 5px; margin: 20px 0;">
                    {code}
                </div>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    Bu kod 5 dakika geçerlidir. Eğer bu talebi siz yapmadıysanız, 
                    bu e-postayı görmezden gelebilirsiniz.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                <p style="color: #999; font-size: 12px;">
                    Bu e-posta Yıllık Site tarafından gönderilmiştir.
                </p>
            </div>
        </body>
        </html>
        """
        
        text_content = f"""
        Email Doğrulama Kodu
        
        Hesabınızı oluşturmak için aşağıdaki doğrulama kodunu kullanın:
        
        Doğrulama Kodu: {code}
        
        Bu kod 5 dakika geçerlidir.
        
        Eğer bu talebi siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.
        
        Teşekkürler!
        Yıllık Site
        """
        
        # E-posta gönder
        logger.info(f"Sending verification email to: {email}")
        
        response = resend.Emails.send({
            "from": settings.FROM_EMAIL,
            "to": [email],
            "subject": subject,
            "html": html_content,
            "text": text_content
        })
        
        logger.info(f"Email sent successfully. Response: {response}")
        return True, response
        
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False, str(e)

def send_password_reset_email(email, reset_link):
    """
    Şifre sıfırlama e-postası gönderir
    """
    try:
        resend.api_key = settings.RESEND_API_KEY
        
        subject = "Şifre Sıfırlama - Yıllık Site"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Şifre Sıfırlama</title>
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                <h1 style="color: #333; margin-bottom: 20px;">Şifre Sıfırlama</h1>
                <p style="color: #666; font-size: 16px; margin-bottom: 20px;">
                    Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background-color: #007bff; color: white; padding: 12px 24px; 
                              text-decoration: none; border-radius: 6px; font-weight: bold;">
                        Şifremi Sıfırla
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Bu bağlantı 24 saat geçerlidir. Eğer şifre sıfırlama talebinde bulunmadıysanız, 
                    bu e-postayı görmezden gelebilirsiniz.
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                <p style="color: #999; font-size: 12px;">
                    Bu e-posta Yıllık Site tarafından gönderilmiştir.
                </p>
            </div>
        </body>
        </html>
        """
        
        response = resend.Emails.send({
            "from": settings.FROM_EMAIL,
            "to": [email],
            "subject": subject,
            "html": html_content
        })
        
        logger.info(f"Password reset email sent successfully to: {email}")
        return True, response
        
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        return False, str(e)
