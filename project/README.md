# Property Management System (PMS)

A Property Management System (PMS) built with Django and Django Rest Framework (DRF) to allow landlords, agents, and tenants to manage and view property listings. This project showcases REST API development, user role-based permissions, and advanced UI views (List, Grid, Map, Detail).

## Objective

The objective of this project is to provide a platform where:
- **Landlords/Agents** can manage properties (create, update, delete).
- **Tenants** can view property listings in various formats.
- The platform supports API-based property management and user authentication.

---

## Key Features

- **API Development**: REST APIs for CRUD operations on properties and user authentication.
- **Swagger Integration**: Auto-generated API documentation.
- **Views**: Implement List View, Grid View, Detail View, and Map View.
- **SQL Queries**: Custom SQL queries for filtering based on various property attributes.
- **Authentication**: User registration, login, and role-based permissions (landlord, agent, tenant).
- **JWT Authentication (Optional)**: For more secure, token-based authentication.

---

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Views](#views)
- [Database Models](#database-models)
- [SQL Queries](#sql-queries)
- [Permissions](#permissions)
- [Swagger API Documentation](#swagger-api-documentation)
- [Bonus Features](#bonus-features)
- [License](#license)

---

## Installation

1. **Clone the Repository**:
   
   git clone https://github.com/username/property-management-system.git

2. Navigate to the Project Directory:


cd property-management-system

3. Create a Virtual Environment:


python -m venv env
source env/bin/activate   # For Linux/macOS
env\Scripts\activate   

4. Install Dependencies:


pip install -r requirements.txt

5. Set Up Database:


python manage.py makemigrations
python manage.py migrate

6. Run the Server:


python manage.py runserver

7. Usage
Accessing the Application
Admin Interface: http://localhost:8000/admin 

for admin interface :
create superuser
python manage.py createsuperuser


Swagger Documentation: http://localhost:8000/swagger/

8. API Endpoints

HTTP         Method	Endpoint	            Description

POST	   /properties/	            Create a new property (Landlord/Agent only)
GET	       /properties/	List         all properties (Tenant view)
GET	       /properties/<id>/	    Get details of a property
PUT     	/properties/<id>/	   Update a property (Owner only)
DELETE	  /properties/<id>/	      Delete a property (Owner only)
POST       /login/	                 Log in
POST	  /register/	            Register a new user

9. Views

List View: Displays a paginated list of all properties with filters for price, property type, and location.

Detail View: Shows detailed information of a single property.

Grid View: Properties displayed in a 3-column grid layout.

Map View: OpenStreetMap integration to show property locations with markers.

10. Permissions

Landlord/Agent:
Can create, update, and delete properties.
Only manage properties they have created.

Tenant:
Can view property listings.
Cannot create, update, or delete properties.


11. Authentication
Registration and Login: User registration and login for role-based access.


12. JWT Authentication: Can be used for token-based authentication instead of default session-based authentication.

13. License
This project is licensed under the MIT License.

yaml

--- 

Let me know if there’s anything else you’d like to add!
