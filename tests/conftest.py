import pytest
from sqlmodel import create_engine, SQLModel, Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.main import app
import app.core.db as db
import os

os.environ["WORKER_SYNC"] = "true"

@pytest.fixture(name="session")
def session_fixture():
    # Use in-memory database with StaticPool to share data across connections
    engine = create_engine(
        "sqlite://", 
        connect_args={"check_same_thread": False}, 
        poolclass=StaticPool
    )
    
    # Ensure tables exist
    # Force import of models to ensure they are registered with SQLModel
    import app.models  # noqa: F401
    SQLModel.metadata.create_all(engine)
    
    # Patch the global engine so the app uses our test DB
    original_engine = db.engine
    db.engine = engine
    
    with Session(engine) as session:
        yield session
    
    # Restore original engine
    db.engine = original_engine

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[db.get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="auth_client")
def auth_client_fixture(client: TestClient):
    """Provides a client with a default user's API key in headers."""
    # First register a user
    client.post("/api/v1/auth/register", json={"email": "testuser@example.com", "password": "testpassword"})
    # Then generate an API key
    # Get a bearer token first
    token_resp = client.post("/api/v1/auth/token", data={"username": "testuser@example.com", "password": "testpassword"})
    token = token_resp.json()["access_token"]
    response = client.post("/api/v1/user/api-key", headers={"Authorization": f"Bearer {token}"})
    data = response.json()
    api_key = data["key"]
    client.headers.update({"x-api-key": api_key})
    return client


@pytest.fixture(name="default_user_id")
def default_user_id_fixture(client: TestClient):
    """Provides the UUID of the default test user."""
    # Register user
    client.post("/api/v1/auth/register", json={"email": "idfixture@example.com", "password": "testpassword"})
    # Get profile to get ID
    token_resp = client.post("/api/v1/auth/token", data={"username": "idfixture@example.com", "password": "testpassword"})
    token = token_resp.json()["access_token"]
    response = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {token}"})
    data = response.json()
    from uuid import UUID
    return UUID(data["id"])

