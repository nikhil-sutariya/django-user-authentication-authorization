from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('login/', views.LoginView.as_view(), name ='login-user'), # Login user and send otp
    path('login/verify-otp/', views.VerifyOtpView.as_view(), name ='verify-otp'), # Verify user using otp
    path('login/refresh/', jwt_views.TokenRefreshView.as_view(), name ='token-refresh'), # Get access token from resfresh token
    path('logout/', views.LogoutView.as_view(), name = 'logout-user'), # Logout user
    path('register/', views.RegisterView.as_view(), name ='register-user'), # Addding user
    path('users/', views.UserListView.as_view(), name = 'users'), # List of users
    path('users/<int:pk>/', views.UserDetailsView.as_view(), name = 'user'), # Retrieve, update particular user's data or delete user
    path('company/list-company/', views.ListCompanyView.as_view(), name= 'list-company'), # view particular usr's detials
    path('company/add-company/', views.AddCompanyView.as_view(), name= 'add-company'), # add company 
    path('company/view-company/<int:pk>/', views.ViewCompanyView.as_view(), name= 'view-company'), # view company a particular company with company creator
    path('company/view-company-customer/<int:company_id>/', views.ViewCompanyCustomerView.as_view(), name= 'view-company-customer'), # view company a particular company with associated users
    path('company/update-company/<int:pk>/', views.UpdateCompanyView.as_view(), name= 'update-company'), # update company a particular company
    path('company/list-customer/', views.ListCustomerView.as_view(), name= 'list-customer'), # list all customers in a database 
    path('company/add-customer/', views.AddCustomerView.as_view(), name= 'add-customer'),  # add customer in a company
    path('users/change_password/<str:pk>/', views.ChangePasswordView.as_view(),name='auth_change_password'), # change password
    path('forgot-password/reset-email/', views.RequestPasswordResetEmailAPI.as_view(), name='request-reset-email'),
    path('forgot-password/<uidb64>&<token>', views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('forgot-password/reset-complete/', views.SetNewPasswordAPI.as_view(), name='password-reset-complete'),
]
