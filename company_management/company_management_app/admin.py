from django.contrib import admin
from .models import *
from django.utils.translation import gettext_lazy as _

''' UserAdmin class helps to display users details in django admin panel '''

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    add_form_template = 'admin/auth/user/add_form.html'
    change_user_password_template = None
    fieldsets = (
        (_('User credential'), {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone', 'role')}),
        (_('Verification'), {'fields': ('email_otp', )}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )

    list_display = ('email', 'first_name', 'last_name', 'phone', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('phone', 'first_name', 'last_name', 'email')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)

''' CompanyAdmin class helps to display company details in django admin panel '''

@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    fieldsets = (
        (_('Company Details'), {'fields': ('company_id', 'company_name', 'company_address')}),
        (_('Company Contact Details'), {'fields': ('company_contact_first_name', 'company_contact_last_name', 'company_contact_email')}),
        (_('Company creator'), {'fields': ('created_by', )}),
        (_('Permissions'), {
            'fields': ('is_active', ),
        }),
    )
    list_display = ('company_name', 'company_contact_email', 'company_id')

''' CustomerAdmin class helps to display customers details of a company in django admin panel '''

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    fieldsets = (
        (_('User credential'), {'fields': ('company_id','email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone', 'role')}),
        (_('Verification'), {'fields': ('email_otp', )}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )

    list_display = ('email', 'first_name', 'last_name', 'phone', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('phone', 'first_name', 'last_name', 'email')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)
