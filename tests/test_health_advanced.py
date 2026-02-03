import pytest
from unittest.mock import patch, MagicMock

@patch("app.main.Session")
@patch("redis.Redis.from_url")
@patch("rq.Worker.all")
def test_health_endpoint_success(mock_worker_all, mock_redis_from_url, mock_session_class, client):
    """Test health endpoint returns 200 and correct status when all services are ok."""
    
    # Mock DB success
    mock_session = MagicMock()
    mock_session_class.return_value.__enter__.return_value = mock_session
    
    # Mock Redis success
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    mock_redis_from_url.return_value = mock_redis
    
    # Mock Workers
    mock_worker = MagicMock()
    mock_worker.queue_names.return_value = ["scans"]
    mock_worker_all.return_value = [mock_worker]
    
    response = client.get("/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["services"]["database"] == "ok"
    assert data["services"]["redis"] == "ok"
    assert data["services"]["workers"]["count"] == 1
    assert data["services"]["workers"]["status"] == "ok"

@patch("app.main.Session")
@patch("redis.Redis.from_url")
def test_health_endpoint_db_failure(mock_redis_from_url, mock_session_class, client):
    """Test health endpoint returns 503 when database fails."""
    
    # Mock DB failure
    mock_session_class.return_value.__enter__.side_effect = Exception("DB Connection Refused")
    
    # Mock Redis success
    mock_redis = MagicMock()
    mock_redis.ping.return_value = True
    mock_redis_from_url.return_value = mock_redis
    
    response = client.get("/health")
    
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert "error" in data["services"]["database"]
    assert data["services"]["redis"] == "ok"

@patch("app.main.Session")
@patch("redis.Redis.from_url")
def test_health_endpoint_redis_failure(mock_redis_from_url, mock_session_class, client):
    """Test health endpoint returns 503 when redis fails."""
    
    # Mock DB success
    mock_session = MagicMock()
    mock_session_class.return_value.__enter__.return_value = mock_session
    
    # Mock Redis failure
    mock_redis = MagicMock()
    mock_redis.ping.return_value = False
    mock_redis_from_url.return_value = mock_redis
    
    response = client.get("/health")
    
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert data["services"]["database"] == "ok"
    assert data["services"]["redis"] == "failed_ping"
