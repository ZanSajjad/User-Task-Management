
from fastapi import FastAPI, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.staticfiles import StaticFiles

from app.database import get_db
from app.models import User, Task
from app.auth import hash_password, verify_password, get_authenticated_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from app.routes import users, tasks
from datetime import timedelta

app = FastAPI()

# Configure templates
templates = Jinja2Templates(directory="app/templates")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Include routers
app.include_router(users.router)
app.include_router(tasks.router)

@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user)
):
    # If current_user is a RedirectResponse, return it to perform the redirection
    if isinstance(current_user, RedirectResponse):
        return current_user

    # Fetch tasks for the logged-in user
    tasks = db.query(Task).filter(Task.owner_id == current_user.id).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": current_user, "tasks": tasks,})
@app.get("/login")
def login_page(request: Request):
    response = templates.TemplateResponse("login.html", {"request": request})
    return response

@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        print("Email already registered")
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email already registered"})

    hashed_password = hash_password(password)
    new_user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()

    return templates.TemplateResponse("login.html", {"request": request, "message": "Registration successful! Please log in."})

@app.post("/login")
def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    print(access_token_expires)
    access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=access_token_expires)

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)  # Secure cookie
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("access_token")  # Remove the JWT token cookie
    return response