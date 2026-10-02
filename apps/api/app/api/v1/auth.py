from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.core.config import get_settings
from app.core.deps import CurrentUser, DbSession, client_ip
from app.core.ratelimit import limiter
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.schemas.common import LoginRequest, TokenOut, UserOut
from app.services import audit, loginguard

router = APIRouter(prefix="/auth", tags=["auth"])

# Verified against when the username is unknown so response time does not reveal which
# usernames exist.
_DUMMY_HASH = hash_password("not-a-real-password")


@router.post("/login", response_model=TokenOut)
@limiter.limit(get_settings().rate_limit_login)
def login(request: Request, body: LoginRequest, db: DbSession) -> TokenOut:
    wait = loginguard.retry_after(body.username)
    if wait:
        audit.record(db, body.username[:48], "auth.login_throttled", ip=client_ip(request))
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again later.", headers={"Retry-After": str(wait)})

    user = db.scalar(select(User).where(User.username == body.username))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok or not user.is_active:
        loginguard.record_failure(body.username)
        audit.record(db, body.username[:48], "auth.login_failed", ip=client_ip(request))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    loginguard.clear(body.username)
    token, ttl = create_access_token(user.id, user.role)
    audit.record(db, user.username, "auth.login", ip=client_ip(request))
    return TokenOut(access_token=token, expires_in=ttl, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user
