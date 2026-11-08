"""
Authentication service — JWT-based user authentication.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.user import User, UserRole, UserReputation

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: int, role: str) -> tuple[str, int]:
    """Returns (token, expires_in_seconds)."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expiry_minutes)
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, settings.jwt_expiry_minutes * 60


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        return None


def register_user(email: str, username: str, password: str, db: Session) -> User:
    if db.query(User).filter(User.email == email).first():
        raise ValueError("Email already registered.")
    if db.query(User).filter(User.username == username).first():
        raise ValueError("Username already taken.")

    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(password),
        role=UserRole.USER,
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    db.flush()

    db.add(UserReputation(user_id=user.id))
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(email: str, password: str, db: Session) -> Optional[User]:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user


def get_user_by_id(user_id: int, db: Session) -> Optional[User]:
    return db.get(User, user_id)


def ensure_admin_exists(db: Session) -> None:
    """Create the bootstrap admin user if it doesn't exist."""
    existing = db.query(User).filter(User.email == settings.admin_email).first()
    if existing:
        return
    admin = User(
        email=settings.admin_email,
        username="admin",
        hashed_password=hash_password(settings.admin_password),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db.add(admin)
    db.flush()
    db.add(UserReputation(user_id=admin.id, score=100.0))
    db.commit()
