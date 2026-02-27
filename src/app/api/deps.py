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


def get_user_enforce_scan_quota(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user)
) -> Optional[User]:
    """Auth + Rate limit + Monthly Scan Quota enforcement."""
    return get_user_enforce_quota(x_api_key, session, current_user, enforce_quota=True)


def get_user_enforce_quota(
    x_api_key: Optional[str] = Header(None),
    session: Session = Depends(get_session),
    current_user: Optional[User] = Depends(get_current_user),
    enforce_quota: bool = True
) -> Optional[User]:
    """Resolve API key OR logged-in User to User and enforce rate limits.
    """
    # 1. Use logged in user context (JWT)
    if current_user:
        # Differentiate rate limit buckets: 'scans' for writes (quota-sensitive) vs 'api' for reads
        route_name = "scans" if enforce_quota else "api"
        # Give more headroom for read-only operations (default 5x)
        effective_rate = current_user.rate_limit_per_minute if enforce_quota else current_user.rate_limit_per_minute * 5
        q = current_user.quota_per_month if enforce_quota else None
        
        check_rate_limit(user_id=str(current_user.id), route=route_name, rate=effective_rate, quota_per_month=q)
        return current_user

    # 2. Fallback to API Key
    if not x_api_key:
        # anonymous requests counted under special 'anonymous' user id
        check_rate_limit(user_id="__anon__", route="global")
        return None

    statement = select(APIKey).where(APIKey.key == x_api_key, APIKey.revoked == False)
    row = session.exec(statement).one_or_none()
    if not row:
        raise HTTPException(status_code=401, detail="invalid api key")
    
    user = session.get(User, row.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user not found")

    # enforce per-user rate limit and quota
    route_name = "scans" if enforce_quota else "api"
    effective_rate = user.rate_limit_per_minute if enforce_quota else user.rate_limit_per_minute * 5
    q = user.quota_per_month if enforce_quota else None
    
    check_rate_limit(user_id=str(user.id), route=route_name, rate=effective_rate, quota_per_month=q)
    return user
