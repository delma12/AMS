Apprentice Management System 

A system where regualr users have access to apprentice page and logout ability. They can create, only edit their own entries, read all records but cannot delete. Admin users on the otherhand can delete, create, update and read other apprentices and all the users. 


Admin credentials: 
Username: admin
Password: adminpassword

Install: pip install -r requirements.txt
Run: python main.py or uvicorn main:app --reload

Tests can be run with python -m pytest 

Dependencies:
Fast API Modules:

1. FastAPI - Framework for building APIs with Python.
2. Request - Represents incoming HTTP requests, giving access to request data.
3. Depends - Dependency injection for FastAPI helps define database sessions and authentication.
4. HTTPException - Raises HTTP exceptions in endpoints.
5. Cookie - Reads and writes cookies in requests.
6. Response - Represents an HTTP response.
7. Jinja2Templates - Renders HTML templates with Jinja2.

SQLAlchemy Modules:

1. Session - Session for interacting with the database, allowing querying, adding, and deleting.
2. Column, Integer, String, Boolean, Float, ForeignKey, Date - SQLAlchemy column types to define the schema of database models.
3. create_engine - Configures and connects to the database.
4. declarative_base - Base class for creating database models.
5. sessionmaker - Factory for creating new sessions.
6. relationship - Defines relationships between models, e.g., foreign key.

Pydantic Modules:

1. BaseModel - Base class for creating data models with validation.


Database Modules:

1. SessionLocal - Creates a local session for database interactions.
2. init_db - Function to initialise the database with required tables.
3. Base - Base class from which all models inherit.

SEA Project-Specific Modules:
1. Custom data models - User and Apprentice - representing the entities of the app.


Middleware:

1. CORSMiddleware - Middleware for handling CORS, restricting access to the API from different domains.

Passlib Modules:
1. CryptContext - Password hashing and verification.

FastAPI Responses:

1. RedirectResponse - Creates a response that redirects the user to a different URL.

Typing:

1. List - List of objects in function parameters or return types.

StaticFiles:

1. StaticFiles - Utility for serving static files like HTML, CSS, images, or JavaScript.
