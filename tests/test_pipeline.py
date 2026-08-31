import hashlib

def test_ingest_and_verify(test_client):
    sample_payload = '{"src_ip": "192.168.1.100", "dest_port": 443, "action": "deny", "severity": "high", "vendor": "Cisco", "timestamp": "2023-10-12T10:00:00Z"}'
    
    # 1. Ingest
    response = test_client.post("/api/v1/ingest", json={
        "source_id": "fw-01",
        "transport": "syslog",
        "payload": sample_payload
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "event_id" in data
    assert data["status"] == "accepted"
    
    event_id = data["event_id"]
    
    # 2. Check Raw hash matches
    raw_resp = test_client.get(f"/api/v1/events/{event_id}/raw")
    assert raw_resp.status_code == 200
    raw_bytes = raw_resp.content
    assert raw_bytes.decode('utf-8') == sample_payload
    
    expected_hash = hashlib.sha256(sample_payload.encode('utf-8')).hexdigest()
    
    # 3. Parse & Canonical Fields Populated
    canon_resp = test_client.get(f"/api/v1/events/{event_id}")
    assert canon_resp.status_code == 200
    c_data = canon_resp.json()
    
    assert c_data["event_id"] == event_id
    assert c_data["network"]["source_ip"] == "192.168.1.100"
    assert c_data["network"]["destination_port"] == 443
    assert c_data["security"]["action"] == "deny"
    assert c_data["source"]["vendor"] == "Cisco"
