from rest_framework import serializers
from .models import Property, PropertyType, CustomUser




class PropertyTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PropertyType
        fields = '__all__'

class PropertySerializer(serializers.ModelSerializer):
    # Use PrimaryKeyRelatedField for ManyToMany relationships
    property_type = serializers.PrimaryKeyRelatedField(queryset=PropertyType.objects.all(), many=True)

    class Meta:
        model = Property
        fields = '__all__'

    def create(self, validated_data):
        # Extract property_type data
        property_type_data = validated_data.pop('property_type')
        
        # Create the Property instance
        property_instance = Property.objects.create(**validated_data)
        
        # Set the ManyToMany field with provided data
        property_instance.property_type.set(property_type_data)
        
        return property_instance

    def update(self, instance, validated_data):
        # Extract property_type data if present
        property_type_data = validated_data.pop('property_type', None)
        
        # Update the Property instance fields
        instance = super().update(instance, validated_data)
        
        # If property_type data is provided, update the ManyToMany field
        if property_type_data is not None:
            instance.property_type.set(property_type_data)
        
        return instance
        
class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # Ensure password is write-only

    class Meta:
        model = CustomUser
        fields = ['id', 'first_name', 'last_name', 'email', 'role', 'password']

    def create(self, validated_data):
        # Create a new user with hashed password
        user = CustomUser(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            role=validated_data['role']
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
        
        
