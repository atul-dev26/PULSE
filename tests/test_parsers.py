def test_syslog_ingestion(test_client):
    syslog_payload = '<34>Oct 11 22:14:15 mymachine customapp: src=10.0.0.1 dst=8.8.8.8 action=deny msg=drop'
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "test-syslog",
        "transport": "TCP",
        "payload": syslog_payload
    })
    data = res.json()
    assert res.status_code == 200
    assert data["format"] == "syslog"
    assert data["status"] == "accepted"
    
    # Check canonical
    ev_res = test_client.get(f"/api/v1/events/{data['event_id']}")
    assert ev_res.status_code == 200
    ev = ev_res.json()
    assert ev["source"]["device_id"] == "mymachine"
    assert ev["network"]["source_ip"] == "10.0.0.1"
    assert ev["network"]["destination_ip"] == "8.8.8.8"
    assert ev["security"]["action"] == "deny"
    assert ev["provenance"]["parser_id"] == "syslog_parser"

def test_cef_ingestion(test_client):
    cef_payload = 'CEF:0|Fortinet|FortiGate|v7.0|1001|Deny Traffic|3|src=10.0.0.5 dst=8.8.8.8 spt=49122 dpt=443 act=deny'
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "test-cef",
        "transport": "TCP",
        "payload": cef_payload
    })
    data = res.json()
    assert res.status_code == 200
    assert data["format"] == "CEF"
    assert data["status"] == "accepted"
    
    # Check canonical
    ev_res = test_client.get(f"/api/v1/events/{data['event_id']}")
    assert ev_res.status_code == 200
    ev = ev_res.json()
    assert ev["source"]["vendor"] == "Fortinet"
    assert ev["source"]["product"] == "FortiGate"
    assert ev["network"]["source_ip"] == "10.0.0.5"
    assert ev["network"]["destination_ip"] == "8.8.8.8"
    assert ev["network"]["source_port"] == 49122
    assert ev["network"]["destination_port"] == 443
    assert ev["security"]["action"] == "deny"
    assert ev["security"]["severity"] == "3"
    assert ev["provenance"]["parser_id"] == "cef_parser"

def test_unknown_format_ingestion(test_client):
    payload = "??!!@@##"
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "test-unknown",
        "transport": "HTTP",
        "payload": payload
    })
    data = res.json()
    assert res.status_code == 200
    assert data["format"] == "unknown"
    assert data["status"] == "accepted"
    assert data["note"] == "stored raw, not parsed"
    
    # Should not exist in canonical events
    ev_res = test_client.get(f"/api/v1/events/{data['event_id']}")
    assert ev_res.status_code == 404
    
    # Should exist in raw events
    raw_res = test_client.get(f"/api/v1/events/{data['event_id']}/raw")
    assert raw_res.status_code == 200
    assert raw_res.content.decode() == payload
    
def test_drain3_fallback(test_client):
    lines = [
        "User bob failed login from 10.1.2.3",
        "User alice failed login from 10.5.5.5",
        "User charlie failed login from 192.168.1.1"
    ]
    
    event_ids = []
    
    for line in lines:
        res = test_client.post("/api/v1/ingest", json={
            "source_id": "test-drain3",
            "transport": "HTTP",
            "payload": line
        })
        data = res.json()
        assert res.status_code == 200
        assert data["format"] == "drain3"
        event_ids.append(data["event_id"])
        
    # Now retrieve events and check clustering
    templates = set()
    for eid in event_ids:
        ev_res = test_client.get(f"/api/v1/events/{eid}")
        assert ev_res.status_code == 200
        ev = ev_res.json()
        assert ev["provenance"]["parser_id"] == "drain3_parser"
        templates.add(ev["provenance"]["raw_template"])
        
        # Checking to see that properties mapped due to `resolve_field` hint fallback
        # Wait, the action 'failed' might have resolved, and the IP might have resolved.
        # "User bob failed login from 10.1.2.3" -> params: ['bob', '10.1.2.3']
        # The wildcards in Drain3 usually replace tokens not found, but it learns.
        # After 3 lines, it should generalize to "User <*> failed login from <*>"
        
    assert len(templates) == 1, "All 3 similar logs should cluster into same template"
