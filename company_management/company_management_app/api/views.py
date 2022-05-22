from rest_framework import generics, views, status
from .serializers import *
from company_management_app.models import *
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from company_management_app.utils import *
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import login
from .permissions import *
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError, force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.filters import SearchFilter, OrderingFilter
from django.template.loader import get_template

''' RegisterView for adding user '''

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data = user)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        user_data = serializer.data
        return Response(user_data, status = status.HTTP_201_CREATED)

''' UserListView for display list of users '''

class UserListView(generics.ListAPIView):
    # permission_classes = (IsAuthenticated, )
    queryset = User.objects.all()
    serializer_class = UserSerializer
    filter_backends = [SearchFilter,OrderingFilter]
    search_fields = ['first_name','last_name']
    ordering_fields = '__all__'

''' UserDetailsView for list, update and delete particluar user '''

class UserDetailsView(generics.RetrieveUpdateDestroyAPIView):
    # permission_classes = (IsAuthenticated, )
    queryset = User.objects.all()
    serializer_class = UserSerializer

''' LoginView is managing user login using user's email and password.
    After submiting email an password user get an email for email otp. '''

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        
        if not user:
            raise AuthenticationFailed('Invalid credentials')

        if user is not None:
            Utils.send_otp_email(user.email, user)
            context = {
                "fname" : user.first_name,
                "lname": user.last_name,
                "otp" : str(user.email_otp)
            }
            email_body = get_template('email_templates/email-otp.html').render(context)
            # email_body = 'Hi '+ user.email + ', Here is your PIN to logging in the Fortified Logic customer portal Click below link to verify your PIN. \nYour PIN is - ' + str(user.email_otp) + '\n'
            data = {'email_subject': 'Email PIN verification', 'email_body': email_body, 'to_email': user.email}
            Utils.send_email(data)
            return Response({'data':serializer.data, 'otp': user.email_otp}, status = status.HTTP_200_OK)

        return Response(serializer.data, status = status.HTTP_403_FORBIDDEN)

''' VerifyOtpView for verifying otp '''

class VerifyOtpView(generics.GenericAPIView):
    serializer_class = VerifyOtpSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception = True)
            user_data = serializer.data
            user = User.objects.get(email = user_data['email']) 

            if user.email_otp == user_data['email_otp']:
                user.is_email_otp_verified = True
                refresh = RefreshToken.for_user(user)
                login(request, user)

                if user.role == "Super Admin":
                    return Response({
                        'userId': user.id,
                        'firstName': user.first_name,
                        'lastName': user.last_name,
                        'userEmail': user.email,
                        'userRole': user.role,
                        'refreshToken' : str(refresh),
                        'accessToken' : str(refresh.access_token)
                    }, status=status.HTTP_200_OK)
                
                elif user.role == "Company Admin" or "Company Viewer":
                    customer = Customer.objects.get(email = user.email)
                    print('@@@@',customer)
                    company = customer.company_id
                    return Response({
                        'userId': user.id,
                        'firstName': user.first_name,
                        'lastName': user.last_name,
                        'userEmail': user.email,
                        'userRole': user.role,
                        'userCompany': company.company_name,
                        'refreshToken' : str(refresh),
                        'accessToken' : str(refresh.access_token)
                    }, status=status.HTTP_200_OK)
        
            return Response({'success': False, 'message': 'Your otp is wrong or expired'}, status = status.HTTP_403_FORBIDDEN)

        except Exception as e:
            print(e)
        return Response({'success': False, 'message': 'Something went wrong'}, status = status.HTTP_403_FORBIDDEN)
        
    ''' Patch function is used for resending otp '''

    def patch(self,request):
        try:
            serializer = self.serializer_class(data = request.data)
            serializer.is_valid(raise_exception = True)      
            user_data = serializer.data
            user = User.objects.get(email = user_data['email']) 
            
            status_new , time = Utils.send_otp_email(user.email, user)
            
            if status_new:
                context = {
                    "fname" : user.first_name,
                    "lname": user.last_name,
                    "otp" : str(user.email_otp)
                }
                email_body = get_template('email_templates/email-otp.html').render(context)
                # email_body = 'Hi '+ user.email + ', Here is your PIN to logging in the Fortified Logic customer portal Click below link to verify your PIN. \nYour PIN is - ' + str(user.email_otp) + '\n' 
                data = {'email_subject': 'Resend PIN verification', 'email_body': email_body, 'to_email': user.email}
                Utils.send_email(data)
                return Response({'message':'new otp sent', 'otp': user.email_otp}, status=status.HTTP_200_OK)
            
            return Response({'error': f'try after few seconds {time}'}, status = status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print(e)
        return Response({'success': False, 'message': 'Something went wrong'}, status = status.HTTP_403_FORBIDDEN)

''' LogoutView is for logging out user '''

class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()
        return Response({'message': 'User successfully logged out'}, status= status.HTTP_200_OK)

''' ListCompanyView is for getting list of added companies '''

class ListCompanyView(generics.ListAPIView):
    # permission_classes = (IsSuperAdmin | IsCompanyAdmin | IsCompanyViewer, IsAuthenticated, )
    serializer_class = CompanySerializer

    # queryset = Company.objects.filter(is_active = True)
    queryset = Company.objects.all()
    
    filter_backends = [SearchFilter,OrderingFilter]
    search_fields = ['company_name']
    ordering_fields = '__all__'

''' AddCompanyView is for adding a new company only by Super Admin '''

class AddCompanyView(generics.GenericAPIView):
    permission_classes = (IsSuperAdmin, IsAuthenticated, )
    serializer_class = CompanySerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()
        return Response(serializer.data, status= status.HTTP_200_OK)

''' UdpateCompanyView is for updating existing company's details only by Super Admin '''

class UpdateCompanyView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsSuperAdmin, IsAuthenticated, )
    serializer_class = UpdateCompanySerializer

    queryset = Company.objects.all()
    lookup_field = 'pk'

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status = status.HTTP_200_OK)

        else:
            return Response({"message": "failed", "details": serializer.errors})

''' ViewCompanyView is for viewing existing company's details '''

class ViewCompanyView(views.APIView):
    permission_classes = (IsSuperAdmin | IsCompanyAdmin | IsCompanyViewer, IsAuthenticated, )

    def get(self, request, pk):
        company = Company.objects.filter(company_id = pk)
        user = User.objects.filter(company = pk)
        company_serializer = CompanySerializer(company, many=True)
        user_serializer = UserSerializer(user, many=True)
        return Response({'company_data':company_serializer.data, 'user_data': user_serializer.data})

''' ViewCompanyCustomerView is for viewing existing company's details with its customers '''

class ViewCompanyCustomerView(generics.ListAPIView):
    permission_classes = (IsSuperAdmin | IsCompanyAdmin | IsCompanyViewer, IsAuthenticated, )
    serializer_class = CustomerSerializer

    filter_backends = [SearchFilter,OrderingFilter]
    search_fields = ['first_name','last_name', 'email']
    ordering_fields = '__all__'
    
    def get_queryset(self):
        customer = Customer.objects.filter(company_id=self.kwargs['company_id']).select_related()
        return customer

''' ListCustomerView is for listing customers in a company '''

class ListCustomerView(generics.ListAPIView):
    permission_classes = (IsSuperAdmin | IsCompanyAdmin | IsCompanyViewer, IsAuthenticated, )
    serializer_class = CustomerSerializer

    queryset = Customer.objects.all()

    filter_backends = [SearchFilter,OrderingFilter]
    search_fields = ['first_name','last_name']
    ordering_fields = '__all__'

''' AddCustomerView is for adding customer in a company and sending email to customer '''

class AddCustomerView(generics.GenericAPIView):
    permission_classes = (IsSuperAdmin | IsCompanyAdmin, IsAuthenticated, )
    serializer_class = CustomerSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        user_data = serializer.data
        user = Customer.objects.get(email = user_data['email'])

        current_site = get_current_site(request).domain
        relativeLink = reverse('login')
        absurl = 'http://'+ current_site + relativeLink
        email_body = 'Hi '+ user.email + ', You are invited to login into Fortified Customer Portal. Use your email address as username and your temporary password is - ' + user_data['password'] + '\n Change password after login.' + absurl
        data = {'email_subject': 'Email PIN verification', 'email_body': email_body, 'to_email': user.email}
        Utils.send_email(data)
        
        return Response(serializer.data, status= status.HTTP_200_OK)

''' Change Password View '''
class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

# Reset Password API
class RequestPasswordResetEmailAPI(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = f'http://{current_site}{relativeLink}?token={str(token)}'
            email_body = ('Hello, \n use link below to reset your password \n' + absurl)
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your password'}
            Utils.send_email(data)
            return Response({'success': 'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'email not exists please enter regisetr email.'}, status=status.HTTP_400_BAD_REQUEST)

class PasswordTokenCheckAPI(views.APIView):
    # serializer_class = ResetPasswordEmailRequestSerializer
    def get(self, request, uidb64, token):
        try:
            uuid = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uuid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)
        