import pytest
from unittest.mock import patch, MagicMock
from uuid import uuid4
from app.services.scanner import schedule_scan
from app.models import Scan
from sqlmodel import Session, create_engine, SQLModel

# Setup in-memory DB for test
engine = create_engine("sqlite:///:memory:")

@pytest.fixture
def db_session():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    SQLModel.metadata.drop_all(engine)

@patch("git.Repo.clone_from")
@patch("app.services.scanner.Session")
def test_private_repo_clone_with_token(mock_session_class, mock_clone, db_session):
    """Test that git_token is correctly injected into the clone URL."""
    
    # Create a scan with a token
    scan_id = uuid4()
    scan = Scan(
        id=scan_id,
        repo_url="https://github.com/user/private-repo.git",
        git_token="my-secret-token",
        status="queued"
    )
    
    # Mock DB session behavior
    mock_session = MagicMock()
    mock_session_class.return_value = mock_session
    mock_session.get.return_value = scan
    
    # Mock scanners to avoid running them
    with patch("app.services.scanners.SemgrepScanner"), \
         patch("app.services.scanners.BanditScanner"), \
         patch("app.services.scanners.PipAuditScanner"), \
         patch("app.services.scanners.CheckovScanner"), \
         patch("app.services.scanners.OSVScanner"), \
         patch("shutil.rmtree"):
        
        # We don't want the actual scan logic to run (database commits etc.)
        # so we just test the clone part by catching the next exception 
        # or letting it fail safely after clone.
        # However, it's cleaner to just test that Repo.clone_from was called correctly.
        
        try:
            schedule_scan(scan_id)
        except Exception:
            pass # We expect failures downstream because we didn't mock everything
        
        # Assert clone_from was called with the authenticated URL
        args, kwargs = mock_clone.call_args
        called_url = args[0]
        
        assert "my-secret-token@github.com" in called_url
        assert "https://my-secret-token@github.com/user/private-repo.git" == called_url
