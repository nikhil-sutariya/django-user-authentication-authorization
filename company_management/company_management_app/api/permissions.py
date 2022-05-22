from rest_framework.permissions import BasePermission

''' Role based custom permission classes for managing oprations like only super admin can create company and
    company admin can add customer having company viewer role '''

class IsSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        is_super_admin = request.user.role == 'Super Admin'
        return is_super_admin

class IsCompanyAdmin(BasePermission):
    def has_permission(self, request, view):
        is_company_admin = request.user.role == 'Company Admin'
        return is_company_admin

class IsCompanyViewer(BasePermission):
    def has_permission(self, request, view):
        is_company_viewer = request.user.role == 'Company Viewer'
        return is_company_viewer
