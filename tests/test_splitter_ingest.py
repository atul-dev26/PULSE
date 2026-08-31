import pytest

def test_ingest_json_array(test_client):
    """Test passing a JSON array of 4 logs -> creates 4 distinct events."""
    payload = '''[
        {"src": "10.0.0.1", "dest": "1.1.1.1", "action": "allow"},
        {"src": "10.0.0.2", "dest": "1.1.1.1", "action": "deny"},
        {"src": "10.0.0.3", "dest": "1.1.1.1", "action": "drop"},
        {"src": "10.0.0.4", "dest": "1.1.1.1", "action": "allow"}
    ]'''
    
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "array-src",
        "transport": "HTTP",
        "payload": payload
    })
    
    assert res.status_code == 200
    data = res.json()
    assert data.get("batch") is True
    assert data["total_logs_detected"] == 4
    assert len(data["results"]) == 4
    for r in data["results"]:
        assert r["status"] == "accepted"
        assert "event_id" in r

def test_ingest_ndjson(test_client):
    """Test passing an NDJSON blob of 3 standalone JSON objects -> creates 3 distinct events."""
    payload = '{"src": "192.168.1.1"}\n{"src": "192.168.1.2"}\n{"src": "192.168.1.3"}'
    
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "ndjson-src",
        "transport": "HTTP",
        "payload": payload
    })
    
    assert res.status_code == 200
    data = res.json()
    assert data.get("batch") is True
    assert data["total_logs_detected"] == 3
    assert len(data["results"]) == 3

def test_ingest_syslog_multiline(test_client):
    """Test passing a multi-line blob of 3 syslog lines -> creates 3 distinct events."""
    payload = "<34>Oct 11 22:14:15 mymachine app1: msg\n<34>Oct 11 22:14:16 mymachine app2: msg\n<34>Oct 11 22:14:17 mymachine app3: msg"
    
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "syslog-multi-src",
        "transport": "HTTP",
        "payload": payload
    })
    
    assert res.status_code == 200
    data = res.json()
    assert data.get("batch") is True
    assert data["total_logs_detected"] == 3
    assert len(data["results"]) == 3

def test_ingest_single_json_object(test_client):
    """Test passing a single ordinary JSON object -> returns original single-event shape."""
    payload = '{"src": "10.1.1.1", "action": "deny"}'
    
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "single-json-src",
        "transport": "HTTP",
        "payload": payload
    })
    
    assert res.status_code == 200
    data = res.json()
    assert data.get("batch") is None  # Make sure it didn't return the batch wrapper
    assert data["status"] == "accepted"
    assert "event_id" in data

def test_ingest_single_syslog(test_client):
    """Test passing a single Syslog line -> returns original single-event shape."""
    payload = "<34>Oct 11 22:14:15 mymachine app: msg"
    
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "single-syslog-src",
        "transport": "HTTP",
        "payload": payload
    })
    
    assert res.status_code == 200
    data = res.json()
    assert data.get("batch") is None
    assert data["status"] == "accepted"
    assert "event_id" in data
