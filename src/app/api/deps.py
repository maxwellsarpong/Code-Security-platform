from fastapi import Header, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlmodel import Session, select
from typing import Optional
from ..models import APIKey, User
from ..core.db import get_session
from ..core.rate_limiter import check_rate_limit
from ..core.auth import SECRET_KEY, ALGORITHM
from ..schemas import TokenData

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)


def get_current_user(
    session: Session = Depends(get_session), token: Optional[str] = Depends(oauth2_scheme)
) -> Optional[User]:
    if not token:
        return None
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    statement = select(User).where(User.email == token_data.email)
    user = session.exec(statement).first()
    if user is None:
        raise credentials_exception
    return user


def get_user_from_api_key(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user)
) -> Optional[User]:
    """Basic auth + Rate limit (per min), but NO monthly quota check."""
    return get_user_enforce_quota(x_api_key, session, current_user, enforce_quota=False)


def get_user_no_quota(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user)
) -> Optional[User]:
    """Alias for clear intent in routes that MUST bypass quota (like renewal)."""
    return get_user_from_api_key(x_api_key, session, current_user)


def get_current_superuser(
    user: Optional[User] = Depends(get_user_no_quota)
) -> User:
    """Dependency that ensures the authenticated user is a superuser."""
    if not user:
         raise HTTPException(status_code=401, detail="Authentication required")
    if not user.is_superuser:
         raise HTTPException(status_code=403, detail="Superuser required")
    return user


def get_user_enforce_scan_quota(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user)
) -> Optional[User]:
    """Auth + Rate limit + Monthly Scan Quota enforcement."""
    return get_user_enforce_quota(x_api_key, session, current_user, enforce_quota="scan")


def get_user_enforce_resolve_quota(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user)
) -> Optional[User]:
    """Auth + Rate limit + Monthly Resolve Quota enforcement."""
    return get_user_enforce_quota(x_api_key, session, current_user, enforce_quota="resolve")


def get_user_enforce_quota(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user),
    enforce_quota: str | bool = False  # 'scan', 'resolve', or False
) -> Optional[User]:
    """Resolve API key OR logged-in User to User and enforce rate limits."""
    # Normalise legacy bool callers
    if enforce_quota is True:
        enforce_quota = "scan"
    elif enforce_quota is False:
        enforce_quota = ""

    def _check(user: User):
        route = enforce_quota if enforce_quota in ("scans", "resolve") else (
            "scans" if enforce_quota == "scan" else ("resolve" if enforce_quota == "resolve" else "api")
        )
        is_scan = enforce_quota == "scan"
        is_resolve = enforce_quota == "resolve"
        effective_rate = user.rate_limit_per_minute if (is_scan or is_resolve) else user.rate_limit_per_minute * 5
        
        scan_quota = user.scan_quota_per_month if user.scan_quota_per_month is not None else 2
        resolve_quota = user.resolve_quota_per_month if user.resolve_quota_per_month is not None else 2

        check_rate_limit(
            user_id=str(user.id),
            route=route,
            rate=effective_rate,
            quota_per_month=scan_quota if is_scan else None,
            resolve_quota_per_month=resolve_quota if is_resolve else None,
        )

    # 1. Use logged-in user context (JWT)
    if current_user:
        _check(current_user)
        return current_user

    # 2. Fallback to API Key
    if not x_api_key:
        check_rate_limit(user_id="__anon__", route="global")
        return None

    statement = select(APIKey).where(APIKey.key == x_api_key, APIKey.revoked == False)
    row = session.exec(statement).one_or_none()
    if not row:
        raise HTTPException(status_code=401, detail="invalid api key")

    user = session.get(User, row.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")

    _check(user)
    return user
