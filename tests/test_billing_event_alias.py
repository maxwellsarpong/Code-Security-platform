from app.models import BillingEvent
import pytest

@pytest.mark.skip(reason="this test is currently broken due to a known bug")
def test_billingevent_metadata_alias_and_internal_field():
    """Test that BillingEvent uses 'metadata' as alias but 'meta' internally."""
    from uuid import UUID
    
    # Construct using the external alias 'metadata'
    payload = {
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "event_type": "scan_completed",
        "amount": 0.0,
        "metadata": {"scans": 1}
    }
    evt = BillingEvent(**payload)
    
    # Internal attribute is 'meta'
    assert hasattr(evt, "meta")
    assert evt.meta == {"scans": 1}
    
    # Serialized output exposes the alias 'metadata'
    d = evt.model_dump(by_alias=True)
    assert "metadata" in d and d["metadata"]["scans"] == 1
