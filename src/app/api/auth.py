from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from ..core.db import get_session
from ..core.auth import get_password_hash, verify_password, create_access_token
from ..core.billing_plans import get_plan
from ..models import User
from ..schemas import UserCreate, UserRead, Token, LoginRequest

router = APIRouter()


@router.post("/register", response_model=UserRead)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    # Check if user exists
    statement = select(User).where(User.email == user_in.email)
    existing_user = session.exec(statement).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists",
        )
    
    
    # Create User
    plan_config = get_plan("free")
    hashed_password = get_password_hash(user_in.password)
    user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        plan="free",
        scan_quota_per_month=plan_config["scan_quota"],
        resolve_quota_per_month=plan_config["resolve_quota"],
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.post("/init-superuser", response_model=UserRead)
def init_superuser(user_in: UserCreate, session: Session = Depends(get_session)):
    """
    Initializes a superuser account if no superuser currently exists.
    Returns 403 Forbidden if a superuser already exists in the system.
    """
    # Check if ANY superuser exists
    superusers = session.exec(select(User).where(User.is_superuser == True)).all()
    if superusers:
        raise HTTPException(
            status_code=403,
            detail="A superuser already exists. Subsequent superusers must be promoted by an existing admin.",
        )
        
    # Check if requested email is already in use
    existing_user = session.exec(select(User).where(User.email == user_in.email)).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User with this email already exists",
        )
        
    # Create Superuser
    plan_config = get_plan("enterprise")
    hashed_password = get_password_hash(user_in.password)
    user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        plan="enterprise",
        is_superuser=True,
        scan_quota_per_month=plan_config["scan_quota"],
        resolve_quota_per_month=plan_config["resolve_quota"],
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.post("/token", response_model=Token)
def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    """Standard OAuth2 form-data login."""
    return _perform_login(form_data.username, form_data.password, session)


@router.post("/login", response_model=Token)
def login_json(
    login_in: LoginRequest,
    session: Session = Depends(get_session)
):
    """JSON-based login."""
    return _perform_login(login_in.email, login_in.password, session)


def _perform_login(email: str, password: str, session: Session) -> dict:
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(subject=user.email)
    return {"access_token": access_token, "token_type": "bearer"}
