"""Tests for Dead Letter Queue (DLQ) behavior during parsing/normalization failures."""

import pytest

def test_malformed_cef_goes_to_dlq_but_stores_raw(test_client):
    """
    A payload starting with 'CEF:' detects as CEF, but if it lacks the 
    pipe-separated fields or valid extension format, it might fail parsing 
    or normalization.
    Actually, let's just trigger a ValueError in map_to_canonical by 
    sending a JSON payload where a port is a string that can't cast to int.
    """
    
    # Valid JSON, detects as json_parser, but source_port mapping int("not-a-port") will crash.
    payload = '{"src_ip": "1.1.1.1", "src_port": "not-a-port", "action": "allow"}'
    
    # 1. Ingest
    ingest_resp = test_client.post("/api/v1/ingest", json={
        "source_id": "test-dlq-src",
        "transport": "api",
        "payload": payload
    })
    
    # Should still return 200 accepted
    assert ingest_resp.status_code == 200, ingest_resp.text
    d = ingest_resp.json()
    assert d["status"] == "accepted"
    assert d["format"] == "unknown_or_failed"
    assert "sent to DLQ" in d["note"]
    
    event_id = d["event_id"]
    
    # 2. Assert Canonical Event is NOT created
    canon_resp = test_client.get(f"/api/v1/events/{event_id}")
    assert canon_resp.status_code == 404
    
    # 3. Assert Raw Evidence IS retrievable
    raw_resp = test_client.get(f"/api/v1/events/{event_id}/raw")
    assert raw_resp.status_code == 200
    assert raw_resp.content.decode("utf-8") == payload
    
    # 4. Assert DLQ record exists and is correct
    dlq_resp = test_client.get(f"/api/v1/dlq/{event_id}")
    assert dlq_resp.status_code == 200
    dlq_data = dlq_resp.json()
    
    assert dlq_data["event_id"] == event_id
    assert dlq_data["failure_stage"] == "normalization" # since json loaded fine but failed to map
    assert dlq_data["error_code"] == "ValueError"
    assert "not-a-port" in dlq_data["error_message"] or "invalid literal for int()" in dlq_data["error_message"]
    
    # 5. Assert /stats includes dlq_count
    stats_resp = test_client.get("/api/v1/stats")
    stats_data = stats_resp.json()
    assert stats_data["dlq_count"] >= 1
