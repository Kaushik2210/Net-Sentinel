"""Password hashing, JWT handling and role-based access control."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum

import bcrypt
from jose import JWTError, jwt

from app.core.config import get_settings


class Role(StrEnum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


# Higher rank inherits everything below it.
_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


def role_at_least(actual: str, required: Role) -> bool:
    try:
        return _RANK[Role(actual)] >= _RANK[required]
    except ValueError:
        return False


def hash_password(password: str) -> str:
    # bcrypt only considers the first 72 bytes; reject longer input at the API layer.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def create_access_token(subject: str, role: str) -> tuple[str, int]:
    s = get_settings()
    expires = timedelta(minutes=s.access_token_minutes)
    payload = {
        "sub": subject,
        "role": role,
        "exp": datetime.now(UTC) + expires,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm=s.jwt_algorithm), int(expires.total_seconds())


def decode_token(token: str) -> dict | None:
    s = get_settings()
    try:
        return jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    except JWTError:
        return None
