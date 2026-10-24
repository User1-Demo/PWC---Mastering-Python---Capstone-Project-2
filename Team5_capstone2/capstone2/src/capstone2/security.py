from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session
from capstone2.config import get_settings
from capstone2.database import get_db
from capstone2.models import User
pwd=CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()
def hash_password(v): return pwd.hash(v)
def verify_password(v,h): return pwd.verify(v,h)
def create_token(user:User):
    s=get_settings(); exp=datetime.now(timezone.utc)+timedelta(minutes=s.access_token_minutes)
    return jwt.encode({"sub":str(user.id),"role":user.role,"exp":exp},s.jwt_secret,algorithm="HS256")


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        uid = int(
            jwt.decode(
                token,
                get_settings().jwt_secret,
                algorithms=["HS256"]
            )["sub"]
        )
    except (JWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    user = db.get(User, uid)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )

    return user

def require_roles(*roles):
    def dep(user:User=Depends(current_user)):
        if user.role not in roles: raise HTTPException(status.HTTP_403_FORBIDDEN,"Insufficient role")
        return user
    return dep
