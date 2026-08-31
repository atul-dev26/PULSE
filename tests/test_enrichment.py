def test_enrichment_private_ip(test_client):
    # Ingest a log with a private IP and a public IP
    syslog_payload = '<34>Oct 11 22:14:15 mymachine customapp: src=192.168.1.50 dst=8.8.8.8 action=deny msg=drop'
    res = test_client.post("/api/v1/ingest", json={
        "source_id": "test-enrichment",
        "transport": "TCP",
        "payload": syslog_payload
    })
    data = res.json()
    assert res.status_code == 200
    
    ev_res = test_client.get(f"/api/v1/events/{data['event_id']}")
    assert ev_res.status_code == 200
    ev = ev_res.json()
    
    enrichment = ev.get("enrichment", {})
    assert enrichment.get("source_ip_class") == "private"
    assert enrichment.get("destination_ip_class") == "public"
    
    # geo lookup might be None if no DB, but shouldn't crash
    assert "destination_geo_country" in enrichment
