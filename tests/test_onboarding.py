def test_auto_onboarding_lifecycle(test_client):
    # 1. Feed a new source with key=value structure
    payload_1 = "srcAddr=10.2.3.4 destAddr=8.8.8.8 dstPort=443 decision=DENY"
    source_id = "test-onboard-src"
    
    res1 = test_client.post("/api/v1/ingest", json={
        "source_id": source_id,
        "transport": "HTTP",
        "payload": payload_1
    })
    
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["format"] in ("drain3", "unknown")
    
    # Check that a pending source was created
    pend_res = test_client.get("/api/v1/onboarding/pending")
    assert pend_res.status_code == 200
    pending_list = pend_res.json()
    assert any(s["source_id"] == source_id for s in pending_list)
    
    # Get details
    detail_res = test_client.get(f"/api/v1/onboarding/pending/{source_id}")
    assert detail_res.status_code == 200
    source_detail = detail_res.json()
    assert source_detail["status"] == "pending"
    assert "srcAddr" in source_detail["suggested_mapping"]
    assert "destAddr" in source_detail["suggested_mapping"]
    
    # 2. Approve it via the endpoint
    # Let's just approve the suggested mapping directly without overrides for simplicity
    appr_res = test_client.post(f"/api/v1/onboarding/pending/{source_id}/approve", json={"overrides": {}})
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "approved"
    
    # 3. Send a second event from the same source_id
    payload_2 = "srcAddr=192.168.1.10 destAddr=1.1.1.1 dstPort=80 decision=ALLOW"
    res2 = test_client.post("/api/v1/ingest", json={
        "source_id": source_id,
        "transport": "HTTP",
        "payload": payload_2
    })
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["format"] == "auto_onboarded"
    
    # Confirm canonical event got mapped automatically
    canonical_res = test_client.get(f"/api/v1/events/{data2['event_id']}")
    assert canonical_res.status_code == 200
    ev = canonical_res.json()
    assert ev["network"]["source_ip"] == "192.168.1.10"
    assert ev["network"]["destination_ip"] == "1.1.1.1"
    assert ev["network"]["destination_port"] == 80
    assert ev["security"]["action"] == "ALLOW"
    assert ev["provenance"]["parser_id"] == "onboarding_parser"
    
    # 4. Third event does not create duplicate
    payload_3 = "srcAddr=10.0.0.1 destAddr=8.8.8.8 dstPort=53 decision=ALLOW"
    res3 = test_client.post("/api/v1/ingest", json={
        "source_id": source_id,
        "transport": "HTTP",
        "payload": payload_3
    })
    assert res3.status_code == 200
    
    # Ensure it's not pending again
    pend_res2 = test_client.get("/api/v1/onboarding/pending")
    # It shouldn't be in the pending list
    pending_list2 = pend_res2.json()
    assert not any(s["source_id"] == source_id for s in pending_list2)
