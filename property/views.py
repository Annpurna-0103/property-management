# Create your views here.
import json
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.models import User
from django.urls import reverse_lazy
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import random
import requests
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.contrib.auth import get_user_model, logout, authenticate, login
import re
from django.contrib import messages
from rest_framework_simplejwt.tokens import RefreshToken
from pms import settings
from .forms import PropertyForm
from .models import CustomUser ,Property, PropertyType
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.decorators import login_required
from rest_framework.authtoken.models import Token
from rest_framework import generics, status
from rest_framework.response import Response
from django.contrib.auth.views import PasswordResetView
from django.core.paginator import Paginator

# Home page view
def home(request):
    return render(request, 'index.html')

# About page view
def about(request):
    return render(request, 'about.html')

# Contact page view                                                                             
def contact(request):
    return render(request, 'contact.html')

@csrf_exempt
def send_contact_email(request):
    if request.method == "POST":
        print("Email data received") 
        
        # Get the user's input data
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject')
        message = request.POST.get('message')
        
        # Compose email content
        full_message = f"""
        You have received a new message from your contact form.

        Name: {name}
        Email: {email}
        Subject: {subject}

        Message:
        {message}
        """
        
        # Send the email
        send_mail(
            f"New Contact Form Submission: {subject}",  # Email subject
            full_message,  # Email body
            'your-email@example.com',  # Replace with your from email
            ['annutripathi0112@gmail.com'],  # Admin email to receive the message
        )
        
        return JsonResponse({'success': True, 'message': 'Email sent successfully!'})

    return JsonResponse({'success': False, 'message': 'Invalid request.'})

@login_required
def property_list(request):
    # Get the logged-in user
    user = request.user
    
    # Check the user's role
    if user.role == 'landlord':
        # Get only properties owned by the logged-in landlord
        properties = Property.objects.filter(landlord=user)
    else:
        # If the user is not a landlord (assumed to be a tenant), show all properties
        properties = Property.objects.all()

    # Get the category from the request to filter properties
    category = request.GET.get('category', 'all')

    if category == 'for_sale':
        properties = properties.filter(category='for_sale')
    elif category == 'for_rent':
        properties = properties.filter(category='for_rent')

    # Implement pagination
    paginator = Paginator(properties, 5)  # Show 5 properties per page
    page_number = request.GET.get('page')
    properties = paginator.get_page(page_number)

    # Get the current view type from the request
    view_type = request.GET.get('view', 'list')  # Default to list view

    return render(request, 'property-list.html', {
        'properties': properties,
        'category': category,
        'view_type': view_type,  # Pass the current view type to the template
    })

@login_required
def property_grid(request):
    # Get the logged-in user
    user = request.user
    
    # Check the user's role
    if user.role == 'landlord':
        # Get only properties owned by the logged-in landlord
        properties = Property.objects.filter(landlord=user)
    else:
        # If the user is not a landlord (assumed to be a tenant), show all properties
        properties = Property.objects.all()

    # Get the category from the request to filter properties
    category = request.GET.get('category', 'all')

    if category == 'for_sale':
        properties = properties.filter(category='for_sale')
    elif category == 'for_rent':
        properties = properties.filter(category='for_rent')

    # Pagination
    paginator = Paginator(properties, 9)  # Show 9 properties per page
    page_number = request.GET.get('page')  # Get the page number from the request
    properties = paginator.get_page(page_number)  # Get the properties for the requested page

    return render(request, 'property_grid.html', {
        'properties': properties,
        'category': category
    })

@login_required
def property_detail(request, property_id):
    # Fetch the property instance based on the provided ID
    property = get_object_or_404(Property, id=property_id)

    # Check if the user is the landlord of the property
    is_landlord = request.user.role == 'landlord' and property.landlord == request.user

    # Prepare context data to send to the template
    context = {
        'property': property,
        'is_landlord': is_landlord,
    }
    
    # Render the property detail template with the context data
    return render(request, 'property_detail.html', context)

# Property type view
# Property type filtering view
def property_type(request):
    property_types = PropertyType.objects.all()
    selected_type = request.GET.get('type')  # Get the selected type from the query params

    # Filter properties based on the selected type
    properties = Property.objects.filter(property_type__name=selected_type) if selected_type else []

    return render(request, 'property-type.html', {
        'property_types': property_types,
        'properties': properties,
        'selected_type': selected_type,  # Optional: to highlight the selected type
    })

@login_required
def edit_property(request, property_id):
    # Fetch the property instance based on the provided ID
    property = get_object_or_404(Property, id=property_id)

    # Check if the user is the landlord of the property
    if property.landlord != request.user:
        return redirect('property_detail', property_id=property.id)  # Redirect if not allowed

    if request.method == 'POST':
        form = PropertyForm(request.POST, request.FILES, instance=property)
        if form.is_valid():
            form.save()
            return redirect('property_detail', property_id=property.id)  # Redirect after saving
    else:
        form = PropertyForm(instance=property)

    context = {
        'form': form,
        'property': property,
    }
    return render(request, 'edit_property.html', context)

def property_delete(request, property_id):
    property = get_object_or_404(Property, id=property_id)

    # Check if the user is allowed to delete the property
    if request.user == property.landlord:
        property.delete()
        return redirect('property_list')  # Redirect to the property list page after deletion
    else:
        # Optionally, handle the case where a tenant tries to delete a property
        return redirect('property_detail', property_id=property.id)

@login_required
def edit_profile(request):
    user = request.user
    
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        password = request.POST.get('password')

        user.first_name = first_name
        user.last_name = last_name
        user.email = email

        if password:
            user.set_password(password)
            update_session_auth_hash(request, user)

        user.save()
        messages.success(request, 'Your profile has been updated successfully.')

        if user.role == 'landlord':
            return redirect('landlord_dashboard')
        elif user.role == 'tenant':
            return redirect('tenant_dashboard')

    return render(request, 'edit_profile.html', {'user': user})

# Property agent view
def property_agent(request):
    # Fetch all users with the role of 'landlord'
    landlords = CustomUser.objects.filter(role='landlord')

    return render(request, 'property-agent.html', {
        'landlords': landlords
    })

def forgot_password(request):
    return render(request, 'forgot_password.html')

User = get_user_model() 
# Function to handle signup

otp_storage = {}

def signup(request):
    if request.method == 'POST':
        # Parse JSON request body
        data = json.loads(request.body)
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        role = data.get('role')

        errors = {}

        # Validate form fields
        if not first_name or not last_name:
            errors['name'] = "First and last name are required."
        if not email:
            errors['email'] = "Email is required."
        if User.objects.filter(email=email).exists():
            errors['email'] = "Email is already in use."
        if not password or len(password) < 8:
            errors['password'] = "Password must be at least 8 characters long."
        if password != confirm_password:
            errors['confirm_password'] = "Passwords do not match."
        if not role:
            errors['role'] = "Role is required."

        # If there are errors, return them to the front-end
        if errors:
            return JsonResponse({'success': False, 'errors': errors}, status=400)

        # Create user
        user = User.objects.create(
            first_name=first_name,
            last_name=last_name,
            username=email,  # Assuming you're using the email as the username
            email=email,
            password=make_password(password),
            role=role  
        )
        user.save()

        return JsonResponse({'success': True})

    return render(request, 'signup.html')



# Store the OTP temporarily (in-memory for simplicity, but better to store it in the database in production)
otp_storage = {}

def send_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')

        if not email:
            return JsonResponse({'success': False, 'error': 'Email is required'}, status=400)

        # Generate OTP
        otp = random.randint(100000, 999999)
        otp_storage[email] = otp

        # Send OTP via email (configure your email settings)
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp}',
            'annutripathi0112@gmail.com',  # Replace with your sending email
            [email],
            fail_silently=False,
        )

        return JsonResponse({'success': True})

    return JsonResponse({'success': False}, status=405)

def verify_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')  # Ensure this is passed from the frontend
        otp = data.get('otp')  # Ensure this is passed correctly as well

        if not email or not otp:
            return JsonResponse({'success': False, 'error': 'Email and OTP are required'}, status=400)

        try:
            otp = int(otp)  # Ensure OTP is an integer for comparison
        except ValueError:
            return JsonResponse({'success': False, 'error': 'Invalid OTP format'}, status=400)

        # Check if the OTP matches the one stored in otp_storage
        if otp_storage.get(email) == otp:
            del otp_storage[email]  # Clear OTP after successful verification
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Invalid OTP'}, status=400)

    return JsonResponse({'success': False}, status=405)


def signin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Authenticate the user using the email and password
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            # Redirect based on user role
            if user.role == 'landlord':
                return redirect('landlord_dashboard')  # Replace with your landlord dashboard URL name
            elif user.role == 'tenant':
                return redirect('tenant_dashboard')  # Replace with your tenant dashboard URL name
        else:
            # Show error message if authentication fails
            messages.error(request, 'Invalid email or password.')

    # Render the sign in page with error messages if any
    return render(request, 'signin.html', {
        'error': messages.get_messages(request)
    })


def tenant_dashboard(request):
    return render(request, 'tenant_dashboard.html')



class CustomPasswordResetView(PasswordResetView):
    template_name = '  password_reset_form.html'
    email_template_name = 'password_reset_email.html'
    success_url = reverse_lazy('password_reset_done')
    subject_template_name = 'password_reset_subject.txt'

    # Customizing the email sending logic
    def form_valid(self, form):
        email = form.cleaned_data['email']
        # Check if the email exists in your system
        send_mail(
            'Password Reset Request',
            'You requested a password reset. Click the link below to reset your password.',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        return super().form_valid(form)


from rest_framework import generics, permissions, status
from rest_framework.response import Response 
from .models import Property
from .serializers import PropertySerializer,CustomUserSerializer,  UserLoginSerializer
from drf_yasg import openapi
from rest_framework.permissions import AllowAny
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.views import TokenRefreshView

class UserRegistrationView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user",
        request_body=CustomUserSerializer,
        responses={
            status.HTTP_201_CREATED: openapi.Response(
                description="User created successfully",
                schema=CustomUserSerializer
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input data"
            )
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        return serializer.save()

class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="User login to receive JWT tokens",
        request_body=UserLoginSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='User ID'),
                        'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
                        'role': openapi.Schema(type=openapi.TYPE_STRING, description='User role'),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
                        'access': openapi.Schema(type=openapi.TYPE_STRING, description='Access token'),
                    }
                )
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Invalid credentials"
            )
        }
    )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(request, email=email, password=password)

        if user is not None:
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'refresh': str(refresh),          # Refresh token
                'access': str(refresh.access_token),  # Access token
            }, status=status.HTTP_200_OK)

        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Refresh access token using refresh token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
            },
            required=['refresh']
        ),
        responses={
            200: openapi.Response(
                description="Access token refreshed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING, description='New access token'),
                    }
                )
            ),
            401: openapi.Response(
                description="Invalid refresh token"
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class PropertyCreateView(generics.GenericAPIView):
    queryset = Property.objects.all()
    serializer_class = PropertySerializer
    permission_classes = [permissions.AllowAny]  # Allow access to anyone

    @swagger_auto_schema(
        operation_description="Retrieve a list of properties",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="A list of properties",
                schema=PropertySerializer(many=True)
            )
        }
    )

    def get(self, request, *args, **kwargs):
        # View all properties
        properties = self.get_queryset()
        serializer = self.get_serializer(properties, many=True)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Create a new property",
        request_body=PropertySerializer,
        responses={
            status.HTTP_201_CREATED: openapi.Response(
                description="Property created successfully",
                schema=PropertySerializer
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input data"
            )
        }
    )

    def post(self, request, *args, **kwargs):
        # Allow anyone to create a property
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        # Save the property instance
        serializer.save()

class PropertyListView(generics.GenericAPIView):
    queryset = Property.objects.all()
    serializer_class = PropertySerializer
    permission_classes = [permissions.AllowAny]  # Allow access to anyone

    @swagger_auto_schema(
        operation_description="Retrieve a list of properties or a single property by ID",
        manual_parameters=[
            openapi.Parameter('price_min', openapi.IN_QUERY, description="Minimum price to filter properties", type=openapi.TYPE_NUMBER),
            openapi.Parameter('price_max', openapi.IN_QUERY, description="Maximum price to filter properties", type=openapi.TYPE_NUMBER),
            openapi.Parameter('property_type', openapi.IN_QUERY, description="Property type ID to filter properties", type=openapi.TYPE_INTEGER),
            openapi.Parameter('pk', openapi.IN_PATH, description="ID of the property to retrieve", type=openapi.TYPE_INTEGER)
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="A list of properties or a single property",
                schema=PropertySerializer(many=True)  # Response schema for a list of properties
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Property not found"
            )
        }
    )

    def get(self, request, *args, **kwargs):
        property_id = kwargs.get('pk')

        if property_id:
            # Retrieve a single property
            property_instance = self.get_queryset().filter(id=property_id).first()
            if property_instance:
                serializer = self.get_serializer(property_instance)
                return Response(serializer.data)
            else:
                return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        else:
            # List all properties with optional filtering
            properties = self.get_queryset()

            # Apply filtering based on query parameters
            price_min = request.query_params.get('price_min')
            price_max = request.query_params.get('price_max')
            property_type = request.query_params.get('property_type')

            if price_min is not None:
                properties = properties.filter(price__gte=price_min)

            if price_max is not None:
                properties = properties.filter(price__lte=price_max)

            if property_type is not None:
                properties = properties.filter(property_type__id=property_type)

            serializer = self.get_serializer(properties, many=True)
            return Response(serializer.data)

class PropertyUpdateView(generics.GenericAPIView):
    queryset = Property.objects.all()
    serializer_class = PropertySerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Retrieve property details by ID",
        manual_parameters=[
            openapi.Parameter('pk', openapi.IN_PATH, description="ID of the property to retrieve", type=openapi.TYPE_INTEGER)
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Property details retrieved successfully",
                schema=PropertySerializer
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Property not found"
            )
        }
    )
    def get(self, request, *args, **kwargs):
        # Retrieve the property details
        property_id = kwargs.get('pk')
        property_instance = self.get_queryset().filter(id=property_id).first()

        if property_instance:
            serializer = self.get_serializer(property_instance)
            return Response(serializer.data)
        else:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(
        operation_description="Update property details by ID",
        request_body=PropertySerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Property updated successfully",
                schema=PropertySerializer
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid data provided"
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Property not found"
            )
        }
    )
    def put(self, request, *args, **kwargs):
        # Update property details
        property_id = kwargs.get('pk')
        property_instance = self.get_queryset().filter(id=property_id).first()

        if property_instance:
            serializer = self.get_serializer(property_instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data)
        else:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

    def perform_update(self, serializer):
        # Save updates to the property
        serializer.save()

class PropertyDeleteView(generics.GenericAPIView):
    queryset = Property.objects.all()
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Delete a property by ID",
        manual_parameters=[
            openapi.Parameter('pk', openapi.IN_PATH, description="ID of the property to delete", type=openapi.TYPE_INTEGER)
        ],
        responses={
            status.HTTP_204_NO_CONTENT: openapi.Response(
                description="Property deleted successfully"
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Property not found"
            )
        }
    )
    def delete(self, request, *args, **kwargs):
        # Delete a property
        property_id = kwargs.get('pk')
        property_instance = self.get_queryset().filter(id=property_id).first()

        if property_instance:
            self.perform_destroy(property_instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

    def perform_destroy(self, instance):
        # Delete the property instance
        instance.delete()

from django.contrib.auth import logout

@login_required  # Ensures the user is authenticated
def landlord_dashboard(request):
    # Check if the logged-in user is a landlord based on the 'role' attribute
    if request.user.role != 'landlord':
        messages.error(request, "You do not have permission to access this dashboard.")
        return redirect('home')  # Redirect to a home page or any appropriate page

    # Fetch properties for the logged-in landlord
    properties = Property.objects.filter(landlord=request.user)

    # Handle logout confirmation
    if request.method == 'POST' and 'logout' in request.POST:
        logout(request)
        messages.success(request, "You have been logged out successfully.")
        return redirect('login')  # Redirect to login page after logout

    # Render the dashboard with properties
    return render(request, 'landlord_dashboard.html', {'properties': properties})

@login_required  # Ensure the user is logged in before adding a property
def add_property(request):
    if request.method == 'POST':
        form = PropertyForm(request.POST, request.FILES)  # Include FILES for media uploads
        if form.is_valid():
            # Create a new Property instance without saving to the database yet
            property_instance = form.save(commit=False)
            property_instance.landlord = request.user  # Set the landlord as the current user
            
            # Build the location string for OpenStreetMap using city and country
            location = f"{form.cleaned_data['city']}, {form.cleaned_data['country']}"
            nominatim_url = f'https://nominatim.openstreetmap.org/search?q={location}&format=json&addressdetails=1'

            # Add a User-Agent header
            headers = {
                'User-Agent': 'property/1.0 (annutripathi0112@gmail.com)'  # Change to your app name and email
            }

            try:
                # Make the request to Nominatim with the User-Agent header
                response = requests.get(nominatim_url, headers=headers)
                response.raise_for_status()  # Raise an error for bad responses
                data = response.json()  # Attempt to parse JSON
                
                if data:
                    # Set latitude and longitude if the response is successful
                    property_instance.latitude = data[0]['lat']
                    property_instance.longitude = data[0]['lon']
                else:
                    property_instance.latitude = None  # Set to None if not found
                    property_instance.longitude = None  # Set to None if not found

            except requests.exceptions.RequestException as e:
                messages.error(request, f"Error fetching location data: {e}")
                return render(request, 'add_property.html', {'form': form})

            # Save the property instance to the database
            property_instance.save()

            # Handle property types separately if using ManyToManyField
            property_instance.property_type.set(form.cleaned_data['property_type'])

            messages.success(request, 'Property added successfully.')
            return redirect('property_list')  # Adjust the URL name as needed
        else:
            messages.error(request, 'Please correct the errors below.')
            print(form.errors)  # For debugging purposes

    else:
        form = PropertyForm()  # Create a blank form for GET requests

    context = {
        'form': form,
    }
    return render(request, 'add_property.html', context)