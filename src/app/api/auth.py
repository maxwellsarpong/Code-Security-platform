from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from ..core.db import get_session
from ..core.auth import get_password_hash, verify_password, create_access_token, create_password_reset_token, verify_password_reset_token
from ..services.email import send_password_reset_email
from ..core.billing_plans import get_plan
from ..models import User
from ..schemas import UserCreate, UserRead, Token, LoginRequest, PasswordRecoveryRequest, PasswordResetRequest

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


@router.post("/request-password-recovery")
def request_password_recovery(
    request: PasswordRecoveryRequest,
    session: Session = Depends(get_session)
):
    """
    Send an email with a password recovery link.
    Returns success even if the user is not found to prevent email enumeration.
    """
    # Use generic success message
    success_response = {"detail": "If your email is registered, you will receive a password recovery link shortly."}
    
    statement = select(User).where(User.email == request.email)
    user = session.exec(statement).first()
    
    if not user:
        return success_response
        
    # Generate token and "send" email
    token = create_password_reset_token(request.email)
    send_password_reset_email(request.email, token)
    
    return success_response


@router.post("/reset-password")
def reset_password(
    request: PasswordResetRequest,
    session: Session = Depends(get_session)
):
    """
    Reset password using a valid token.
    """
    email = verify_password_reset_token(request.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token."
        )
        
    statement = select(User).where(User.email == email)
    user = session.exec(statement).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
        
    # Update the password
    user.hashed_password = get_password_hash(request.new_password)
    session.add(user)
    session.commit()
    
    return {"detail": "Password has been successfully reset."}


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
