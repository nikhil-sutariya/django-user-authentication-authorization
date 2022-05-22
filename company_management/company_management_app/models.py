from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _

''' UserManager class helps to create user using User model '''

class UserManager(BaseUserManager):
    def _create_user(self, email, phone, password, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        if not phone:
            raise ValueError('Phone number is required')
        email = self.normalize_email(email)
        user = self.model(email=email, phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, phone, password = None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, phone, password, **extra_fields)

    def create_superuser(self, email=None, phone=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, phone, password, **extra_fields)

''' User class is our custom User model for our users '''

class User(AbstractUser):

    ROLE_CHOICES = (
        ('Super Admin', 'Super Admin'),
        ('Company Admin', 'Company Admin'),
        ('Company Viewer', 'Company Viewer')
    )

    username = None
    email = models.EmailField(_('email address'), unique= True)
    phone = models.CharField(_('phone number'), max_length= 10, unique= True)
    role = models.CharField(_('role or title'), max_length= 20, choices= ROLE_CHOICES, blank=True, null=True, default='Company Admin')
    email_otp = models.CharField(_('email otp'), max_length= 4, blank= True, null= True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone']

    objects = UserManager()

    class Meta:
        db_table = "Users"
        verbose_name = "Users"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

''' Company class is our Company model to create and manage companies '''

class Company(models.Model):
    company_id = models.CharField(max_length=50, blank= False, primary_key=True)
    company_name = models.CharField(max_length=50, blank= False, unique= True)
    company_address = models.CharField(max_length=200, blank= False)
    company_contact_first_name = models.CharField(max_length=100, blank= False)
    company_contact_last_name = models.CharField(max_length=100, blank= False)
    company_contact_email = models.EmailField(max_length=100, blank= False)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "Companies"
        verbose_name = "Company"
        verbose_name_plural = "Companies"

    def __str__(self):
        return self.company_name.capitalize()

''' Customer class is our Customer model to create and manage customers in a company '''

class Customer(User):
    company_id = models.ForeignKey(Company, on_delete=models.CASCADE)

    class Meta:
        db_table = "Customer"
        verbose_name = "Customer"

    def __str__(self):
        return self.email
        