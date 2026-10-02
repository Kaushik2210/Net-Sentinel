from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import Role, decode_token, role_at_least
from app.db.session import get_db
from app.models import User

_bearer = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)], db: DbSession
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    payload = decode_token(creds.credentials)
    if not payload:
        raise unauthorized
    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise unauthorized
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require_role(minimum: Role):
    def checker(user: CurrentUser) -> User:
        if not role_at_least(user.role, minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"{minimum.value} role required")
        return user

    return checker


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""
