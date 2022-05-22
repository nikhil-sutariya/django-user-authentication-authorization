from django.core.mail import EmailMessage
from django.core.cache import cache
import pyotp, base64

''' Send_mail function is for sending an email and send_otp_email is for create and 4 digit random number which acts as an otp. '''

class Utils:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.content_subtype ="html"
        email.send()
    
    def send_otp_email(email, user):
        if cache.get(email):
            return False, cache._has_expired(email)
    
        try:
            secret = base64.b32encode(bytearray(user.email, 'ascii')).decode('utf-8')
            totp = pyotp.TOTP(secret, digits = 4, interval=30)
            user.email_otp = totp.now()
            totp = cache.set(email, totp, timeout = 30)
            user.save()
            return True, 0

        except Exception as e:
            print(e)
