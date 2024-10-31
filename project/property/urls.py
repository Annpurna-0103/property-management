from django.urls import path
from .views import *
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    PropertyCreateView,
    PropertyListView,
    PropertyUpdateView,
    PropertyDeleteView,
)

urlpatterns = [
    path('', home, name='home'),  # Home page
    path('about/', about, name='about'),  # About page
    path('contact/', contact, name='contact'),  # Contact page
     path('send-email/', send_contact_email, name='send_contact_email'),
    path('property-list/', property_list, name='property_list'), 
    path('property-grid/', property_grid, name='property_grid'),  # Property listing
    path('property-list/<int:property_id>/', property_detail, name='property_detail'),
    path('property-type/', property_type, name='property_type'),  # Property type
    path('property-agent/', property_agent, name='property_agent'),  # Property agent
    path('signup/', signup, name='signup'),
    path('signin/', signin, name='signin'),
    path('send-otp/', send_otp, name='send_otp'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('landlord_dashboard/', landlord_dashboard, name='landlord_dashboard'),
    path('tenant-dashboard/', tenant_dashboard, name='tenant_dashboard'),
    path('add_property/', add_property, name='add_property'),
    path('edit_property/<int:property_id>/', edit_property, name='edit_property'),
    path('edit_profile/', edit_profile, name='edit_profile'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='password_reset_form.html'), name='password_reset'),     
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),     
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),     
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
     path('property/delete/<int:property_id>/', property_delete, name='property_delete'),

    #API
    path('properties/', PropertyCreateView.as_view(), name='property-create'), # API endpoint for creating properties
    path('properties/list/', PropertyListView.as_view(), name='property-list'),         # List all properties
    path('properties/<int:pk>/', PropertyUpdateView.as_view(), name='property-update'), # Update a property
    path('properties/<int:pk>/delete/', PropertyDeleteView.as_view(), name='property-delete'), # Delete a property
    path('register/', UserRegistrationView.as_view(), name='user-register'),  # Registration API
    path('login/', UserLoginView.as_view(), name='user-login'),             # Login and receive tokens
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh access token
    ]


