from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse
from app.database import get_db
from app.models import User

# JWT settings
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request, db: Session = Depends(get_db)):
    # Get the token from the cookie
    token = request.cookies.get("access_token")
    if not token:
        return None  # No token, user is not authenticated

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None  # Invalid token, user is not authenticated
    except JWTError:
        return None  # Token decoding failed, user is not authenticated

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        return None  # User not found, user is not authenticated

    return user  # User is authenticated

def get_authenticated_user(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        response = RedirectResponse(url="/login", status_code=303)
        response.set_cookie("flash_message", "You need to log in to access this page.")
        return response
    return user