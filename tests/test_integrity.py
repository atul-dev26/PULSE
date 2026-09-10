import pytest
import os


def test_integrity_verify_all_pass(test_client):
    """Ingest 3 events (triggers batch at batch_size=3), verify all return VERIFIED."""
    event_ids = []

    for i in range(3):
        res = test_client.post("/api/v1/ingest", json={
            "source_id": f"integrity-src-{i}",
            "transport": "HTTP",
            "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "accepted"
        event_ids.append(data["event_id"])

    for eid in event_ids:
        v_res = test_client.get(f"/api/v1/events/{eid}/verify")
        assert v_res.status_code == 200
        v_data = v_res.json()
        assert v_data["raw_integrity"] is True
        assert v_data["normalized_integrity"] is True
        assert v_data["chain_integrity"] is True
        assert v_data["merkle_integrity"] is True
        assert v_data["overall"] == "VERIFIED"

    # Also test /trace for the first event
    t_res = test_client.get(f"/api/v1/events/{event_ids[0]}/trace")
    assert t_res.status_code == 200
    t_data = t_res.json()
    assert "raw_hash" in t_data
    assert "normalized_hash" in t_data
    assert "chain_hash" in t_data
    assert t_data["parser_id"] == "json_parser"
    assert t_data["merkle_batch_id"] is not None
    assert t_data["merkle_root"] is not None


def test_tamper_detection(test_client):
    """Tamper with a raw file on disk and confirm /verify detects it."""
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "tamper-src",
        "transport": "HTTP",
        "payload": '{"src": "192.168.1.1", "dest": "192.168.1.2", "action": "allow"}'
    })
    assert res.status_code == 200
    event_id = res.json()["event_id"]

    # Verify passes before tampering
    v_res = test_client.get(f"/api/v1/events/{event_id}/verify")
    assert v_res.status_code == 200
    assert v_res.json()["raw_integrity"] is True
    assert v_res.json()["overall"] == "VERIFIED"

    # Simulate an attacker modifying raw evidence on disk
    raw_path = os.path.join("data", "raw", f"{event_id}.raw")
    with open(raw_path, "wb") as f:
        f.write(b'{"src": "9.9.9.9", "dest": "192.168.1.2", "action": "allow"}')

    # Verify again — should detect tampering
    v_res2 = test_client.get(f"/api/v1/events/{event_id}/verify")
    assert v_res2.status_code == 200
    data = v_res2.json()
    assert data["raw_integrity"] is False
    assert data["overall"] == "TAMPERING_DETECTED"
