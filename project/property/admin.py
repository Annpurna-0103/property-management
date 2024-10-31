from django.contrib import admin

# Register your models here.
from .models import CustomUser, Property, PropertyType # Adjust the import according to your project structure

# Custom User Admin
@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'is_staff', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    list_filter = ('role', 'is_staff', 'is_active')
    ordering = ('-date_joined',)
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role', 'is_active', 'is_staff')}
        ),
    )
    filter_horizontal = ()
    readonly_fields = ('last_login', 'date_joined')

# Property Admin
@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'price', 'landlord', 'created_at', 'updated_at')
    search_fields = ('title', 'address', 'landlord__email')
    list_filter = ('category', 'property_type', 'landlord')
    ordering = ('-created_at',)

class PropertyTypeAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)


admin.site.register(PropertyType, PropertyTypeAdmin)

