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

