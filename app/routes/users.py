from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import timedelta

from app.database import get_db
from app.models import User
from app.auth import (
    hash_password, verify_password, get_authenticated_user,
    create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
)

templates = Jinja2Templates(directory="app/templates")
router = APIRouter(prefix="/users", tags=["Users"])

# Show register page (GET request)
@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# Register user (POST request)
@router.post("/register")
def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email already registered"})

    hashed_password = hash_password(password)
    new_user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()

    return RedirectResponse(url="/users/login", status_code=303)

# Show login page
@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Handle login (POST request)
@router.post("/login")
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
    access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=access_token_expires)

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True)  # Secure cookie
    return response

# Handle logout
@router.get("/logout")
def logout():
    response = RedirectResponse(url="/users/login")
    response.delete_cookie("access_token")  # Remove JWT token cookie
    return response
