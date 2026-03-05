import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from app.models import User
from app.core.auth import create_password_reset_token, get_password_hash, verify_password

def test_request_password_recovery_existing_user(client: TestClient, session: Session):
    """Test requesting a password reset for an existing user."""
    # Create test user
    client.post("/api/v1/auth/register", json={"email": "recoverytest@example.com", "password": "password123"})
    
    response = client.post(
        "/api/v1/auth/request-password-recovery",
        json={"email": "recoverytest@example.com"}
    )
    assert response.status_code == 200
    assert "detail" in response.json()
    assert "If your email is registered" in response.json()["detail"]

def test_request_password_recovery_nonexistent_user(client: TestClient):
    """Test requesting a password reset for a non-existent user."""
    response = client.post(
        "/api/v1/auth/request-password-recovery",
        json={"email": "nobody@example.com"}
    )
    assert response.status_code == 200
    assert "detail" in response.json()
    assert "If your email is registered" in response.json()["detail"]

def test_reset_password_valid_token(client: TestClient, session: Session):
    """Test resetting password with a valid token."""
    # Create test user
    client.post("/api/v1/auth/register", json={"email": "resettest@example.com", "password": "password123"})
    
    # Generate token directly
    token = create_password_reset_token("resettest@example.com")
    new_password = "new_secure_password123!"

    response = client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": new_password}
    )
    assert response.status_code == 200
    assert response.json() == {"detail": "Password has been successfully reset."}

    # Verify password was actually changed using the login endpoint
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "resettest@example.com", "password": new_password}
    )
    assert login_response.status_code == 200

def test_reset_password_invalid_token(client: TestClient):
    """Test resetting password with an invalid token."""
    response = client.post(
        "/api/v1/auth/reset-password",
        json={"token": "invalid_or_expired_token", "new_password": "new_password123!"}
    )
    assert response.status_code == 400
    assert "Invalid or expired password reset token" in response.json()["detail"]
