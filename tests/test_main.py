import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import app, get_db
from database import Base
from fastapi.testclient import TestClient
from models import User
from passlib.context import CryptContext

# Create a new in-memory SQLite database for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///./tests.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the get_db dependency to use the test database
@pytest.fixture(scope="function")
def test_db():
    # Create the database schema (tables)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
    # Drop the schema after the test
    Base.metadata.drop_all(bind=engine)

# Utility to create an admin user for tests
def create_test_admin_user(db):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash("adminpassword")
    admin_user = User(username="admin", hashed_password=hashed_password, is_admin=True)
    db.add(admin_user)
    db.commit()

# Utility to create a normal user for tests
def create_test_user(db, username="testuser", password="testpassword"):
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_password = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed_password, is_admin=False)
    db.add(user)
    db.commit()

# Override FastAPI dependency
@pytest.fixture(scope="function")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            test_db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client

@pytest.fixture(scope="function")
def client_with_admin(test_db):
    # Create admin user for tests
    create_test_admin_user(test_db)

    def override_get_db():
        try:
            yield test_db
        finally:
            test_db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    return client

# Test cases
def test_register_user(client):
    response = client.post("/register", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 200
    assert "Registration successful" in response.text

def test_register_duplicate_user(client, test_db):
    create_test_user(test_db, username="testuser")
    response = client.post("/register", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Username already taken"

def test_login(client, test_db):
    create_test_user(test_db)
    
    response = client.post("/login", data={"username": "testuser", "password": "testpassword"})
    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"

  # Test invalid login
    response = client.post("/login", data={"username": "wronguser", "password": "wrongpassword"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_get_dashboard(client, test_db):
    create_test_user(test_db)
    client.post("/login", data={"username": "testuser", "password": "testpassword"})
    
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Welcome" in response.text

def test_create_user(client_with_admin):
    client = client_with_admin
    response = client.post("/users", json={"username": "newuser", "password": "newpassword", "is_admin": False})
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["username"] == "newuser"
    assert json_data["is_admin"] is False

def test_get_users(client_with_admin, test_db):
    create_test_user(test_db, username="newuser")
    client = client_with_admin
    response = client.get("/users")
    assert response.status_code == 200
    assert "newuser" in response.text  

def test_create_apprentice(client_with_admin):
    client = client_with_admin
    response = client.post("/apprentices", json={
        "name": "John Doe",
        "email": "johndoe@example.com",
        "age": 22,
        "cohort_year": 2024,
        "job_role": "Software Developer",
        "skills": "Python, JavaScript"
    })
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["name"] == "John Doe"
    assert json_data["email"] == "johndoe@example.com"
    assert json_data["cohort_year"] == 2024

def test_get_apprentice(client_with_admin):
    client = client_with_admin
    response = client.get("/apprentices/1")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["name"] == "John Doe"
    assert json_data["email"] == "johndoe@example.com"

def test_update_apprentice(client_with_admin):
    client = client_with_admin
    response = client.put("/apprentices/1", json={
        "name": "John Smith",
        "email": "johnsmith@example.com",
        "age": 23,
        "cohort_year": 2025,
        "job_role": "Backend Developer",
        "skills": "Go, Docker"
    })
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["name"] == "John Smith"
    assert json_data["email"] == "johnsmith@example.com"

def test_delete_apprentice(client_with_admin):
    client = client_with_admin
    response = client.delete("/apprentices/1")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["name"] == "John Smith"

    response = client.get("/apprentices/1")
    assert response.status_code == 404
