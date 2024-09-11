from fastapi import FastAPI, Request, Depends, HTTPException, Cookie
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import SessionLocal, init_db
from models import User
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from fastapi.responses import RedirectResponse


app = FastAPI()
templates = Jinja2Templates(directory="templates")


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
        admin_user = User(username="admin", hashed_password=hashed_password, is_admin=True)
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

class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool
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
    title = f"Welcome, {'Admin' if user.is_admin else user.username}'s Dashboard"
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "title": title, 
        "is_admin": user.is_admin  
    })
