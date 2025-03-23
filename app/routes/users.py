from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models  import User

from app.schemas import UserCreate, UserResponse
from app.auth import hash_password
from fastapi.responses import RedirectResponse
templates = Jinja2Templates(directory="app/templates")

router = APIRouter(prefix="/users", tags=["Users"])

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
    return RedirectResponse(url="/login", status_code=303)