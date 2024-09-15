from fastapi import FastAPI, Request, Depends, HTTPException, Cookie
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import SessionLocal, init_db
from models import User, Apprentice
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from fastapi.responses import RedirectResponse
from typing import List
from fastapi.staticfiles import StaticFiles


app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


init_db()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_admin_user(db: Session):
    if not db.query(User).filter(User.username == "admin").first():
        hashed_password = pwd_context.hash("adminpassword")
        admin_user = User(username="admin",
                          hashed_password=hashed_password, is_admin=True)
        db.add(admin_user)
        db.commit()


@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    try:
        create_admin_user(db)
    finally:
        db.close()


def get_current_user(username: str = Cookie(None), db: Session = Depends(get_db)):
    if not username:
        raise HTTPException(status_code=403, detail="User not authenticated")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def is_admin(user: User):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Unauthorised")


class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: bool = False


class UserUpdate(BaseModel):
    username: str
    password: str = None
    is_admin: bool = False


class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool

    class Config:
        orm_mode = True


class ApprenticeCreate(BaseModel):
    name: str
    email: str
    age: int
    cohort_year: int
    job_role: str
    skills: str


class ApprenticeUpdate(BaseModel):
    name: str
    email: str
    age: int
    cohort_year: int
    job_role: str
    skills: str


class ApprenticeResponse(BaseModel):
    id: int
    name: str
    email: str
    age: int
    cohort_year: int
    job_role: str
    skills: str
    creator_username: str

    class Config:
        orm_mode = True


@app.get('/')
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post('/login', response_class=RedirectResponse)
async def login_post(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    user = db.query(User).filter(User.username == username).first()
    if user and pwd_context.verify(password, user.hashed_password):
        response = RedirectResponse(url='/dashboard', status_code=302)
        response.set_cookie(key="username", value=username)
        return response
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post('/register')
async def register_post(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = form.get("username")
    password = form.get("password")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_password = pwd_context.hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    return templates.TemplateResponse("index.html", {"request": request, "message": "Registration successful! You can now log in."})


@app.get('/dashboard')
async def dashboard(request: Request, user: UserResponse = Depends(get_current_user)):
    title = f"Welcome, {
        'Admin' if user.is_admin else user.username}'s Dashboard"
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "title": title,
        "is_admin": user.is_admin
    })


@app.get('/users', response_model=List[UserResponse])
async def get_users(request: Request, db: Session = Depends(get_db), user: UserResponse = Depends(get_current_user)):
    is_admin(user)
    users = db.query(User).all()
    return templates.TemplateResponse("users.html", {"request": request, "users": users, "is_admin": user.is_admin})


@app.post('/users', response_model=UserResponse)
async def create_user(user_data: UserCreate, db: Session = Depends(get_db), current_user: UserResponse = Depends(get_current_user)):
    is_admin(current_user)
    hashed_password = pwd_context.hash(user_data.password)
    new_user = User(username=user_data.username,
                    hashed_password=hashed_password, is_admin=user_data.is_admin)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.put('/users/{user_id}', response_model=UserResponse)
async def update_user(user_id: int, user_data: UserUpdate, db: Session = Depends(get_db), current_user: UserResponse = Depends(get_current_user)):
    is_admin(current_user)
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    db_user.username = user_data.username
    if user_data.password:
        db_user.hashed_password = pwd_context.hash(user_data.password)
    db_user.is_admin = user_data.is_admin
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()

    if user:
        return user
    else:
        raise HTTPException(status_code=404, detail="User not found")


@app.delete('/users/{user_id}', response_model=UserResponse)
async def delete_user(user_id: int, db: Session = Depends(get_db), current_user: UserResponse = Depends(get_current_user)):
    is_admin(current_user)
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return db_user


@app.get('/apprentices')
async def apprentices(request: Request, db: Session = Depends(get_db), user: UserResponse = Depends(get_current_user)):
    apprentices = db.query(Apprentice).all()
    return templates.TemplateResponse("apprentice.html", {
        "request": request,
        "apprentices": apprentices,
        "is_admin": user.is_admin,
        "current_user": user
    })


@app.post('/apprentices', response_model=ApprenticeResponse)
async def create_apprentice(apprentice_data: ApprenticeCreate, db: Session = Depends(get_db), current_user: UserResponse = Depends(get_current_user)):
    new_apprentice = Apprentice(
        name=apprentice_data.name,
        email=apprentice_data.email,
        age=apprentice_data.age,
        cohort_year=apprentice_data.cohort_year,
        job_role=apprentice_data.job_role,
        skills=apprentice_data.skills,
        creator_id=current_user.id
    )
    db.add(new_apprentice)
    db.commit()
    db.refresh(new_apprentice)

    creator_username = db.query(User.username).filter(
        User.id == current_user.id).scalar()

    return ApprenticeResponse(
        id=new_apprentice.id,
        name=new_apprentice.name,
        email=new_apprentice.email,
        age=new_apprentice.age,
        cohort_year=new_apprentice.cohort_year,
        job_role=new_apprentice.job_role,
        skills=new_apprentice.skills,
        creator_username=creator_username
    )


# getting a specific apprentice via apprenticeId
@app.get('/apprentices/{apprentice_id}', response_model=ApprenticeResponse)
async def get_apprentice(apprentice_id: int, db: Session = Depends(get_db), user: UserResponse = Depends(get_current_user)):
    apprentice = db.query(Apprentice).filter(
        Apprentice.id == apprentice_id).first()
    if not apprentice:
        raise HTTPException(status_code=404, detail="Apprentice not found")

    creator_username = db.query(User.username).filter(
        User.id == apprentice.creator_id).scalar()

    return ApprenticeResponse(
        id=apprentice.id,
        name=apprentice.name,
        email=apprentice.email,
        age=apprentice.age,
        cohort_year=apprentice.cohort_year,
        job_role=apprentice.job_role,
        skills=apprentice.skills,
        creator_username=creator_username
    )


@app.put('/apprentices/{apprentice_id}', response_model=ApprenticeResponse)
async def update_apprentice(apprentice_id: int, apprentice_data: ApprenticeUpdate, db: Session = Depends(get_db), current_user: UserResponse = Depends(get_current_user)):
    db_apprentice = db.query(Apprentice).filter(
        Apprentice.id == apprentice_id).first()

    if not db_apprentice:
        raise HTTPException(status_code=404, detail="Apprentice not found")

    if db_apprentice.creator_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="Not authorized to edit this apprentice")

    db_apprentice.name = apprentice_data.name
    db_apprentice.email = apprentice_data.email
    db_apprentice.age = apprentice_data.age
    db_apprentice.cohort_year = apprentice_data.cohort_year
    db_apprentice.job_role = apprentice_data.job_role
    db_apprentice.skills = apprentice_data.skills

    db.commit()
    db.refresh(db_apprentice)

    return ApprenticeResponse(
        id=db_apprentice.id,
        name=db_apprentice.name,
        email=db_apprentice.email,
        age=db_apprentice.age,
        cohort_year=db_apprentice.cohort_year,
        job_role=db_apprentice.job_role,
        skills=db_apprentice.skills,
        creator_username=current_user.username
    )


@app.delete('/apprentices/{apprentice_id}', response_model=ApprenticeResponse)
async def delete_apprentice(apprentice_id: int, db: Session = Depends(get_db), user: UserResponse = Depends(get_current_user)):
    is_admin(user)

   
    db_apprentice = db.query(Apprentice).filter(
        Apprentice.id == apprentice_id).first()
    if not db_apprentice:
        raise HTTPException(status_code=404, detail="Apprentice not found")

   
    creator = db.query(User).filter(
        User.id == db_apprentice.creator_id).first()

   
    creator_username = creator.username if creator else "Deleted User"

    
    response = ApprenticeResponse(
        id=db_apprentice.id,
        name=db_apprentice.name,
        email=db_apprentice.email,
        age=db_apprentice.age,
        cohort_year=db_apprentice.cohort_year,
        job_role=db_apprentice.job_role,
        skills=db_apprentice.skills,
        creator_username=creator_username  
    )

    
    db.delete(db_apprentice)
    db.commit()

    return response


@app.get('/logout')
async def logout(response: RedirectResponse):
    response.delete_cookie(key="username")
    return RedirectResponse(url='/')
