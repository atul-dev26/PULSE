import pytest
from common.models import BatchRow, IntegrityRecordRow
from tests.conftest import TestingSessionLocal
import os

def test_batches_endpoints(test_client):
    # Ingest 6 events to create 2 batches (batch_size is 3 in MVP)
    for i in range(6):
        res = test_client.post("/api/v1/ingest", json={
            "source_id": f"batch-src-{i}",
            "transport": "HTTP",
            "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
        })
        assert res.status_code == 200

    # 1. Test GET /api/v1/batches
    list_res = test_client.get("/api/v1/batches")
    assert list_res.status_code == 200
    data = list_res.json()
    assert data["total"] >= 2
    assert len(data["data"]) >= 2
    
    batch = data["data"][0] # Latest batch
    batch_id = batch["batch_id"]
    assert "chain_continuous" in batch
    assert batch["chain_continuous"] is True
    
    # 2. Test GET /api/v1/batches/{batch_id}
    detail_res = test_client.get(f"/api/v1/batches/{batch_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["batch_id"] == batch_id
    assert len(detail["event_ids"]) == 3
    assert "chain_continuous" in detail
    assert detail["chain_continuous"] is True
    assert "anchor_log" in detail
    assert detail["anchor_log"]["batch_id"] == batch_id

    # 3. Test POST /api/v1/batches/{batch_id}/reverify (success)
    re_res = test_client.post(f"/api/v1/batches/{batch_id}/reverify")
    assert re_res.status_code == 200
    re_data = re_res.json()
    assert re_data["match"] is True

    # 4. Test GET /api/v1/batches/stats
    stats_res = test_client.get("/api/v1/batches/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_batches"] >= 2
    assert stats["average_batch_size"] == 3.0
    assert stats["overall_chain_continuous"] is True

    # 5. Tamper with DB to break reverify
    db = TestingSessionLocal()
    target_event_id = detail["event_ids"][1]
    record = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == target_event_id).first()
    original_chain_hash = record.chain_hash
    record.chain_hash = "corrupted_hash"
    db.commit()
    db.close()

    re_fail = test_client.post(f"/api/v1/batches/{batch_id}/reverify")
    assert re_fail.status_code == 200
    assert re_fail.json()["match"] is False

    db = TestingSessionLocal()
    record = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == target_event_id).first()
    record.chain_hash = original_chain_hash
    db.commit()
    db.close()

    # 6. Break chain_continuous
    for i in range(6, 9):
        test_client.post("/api/v1/ingest", json={
            "source_id": f"batch-src-{i}",
            "transport": "HTTP",
            "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
        })
        
    db = TestingSessionLocal()
    all_batches = db.query(BatchRow).order_by(BatchRow.created_at.desc()).all()
    latest_batch = all_batches[0]
    target_batch_id = latest_batch.batch_id
    first_evt = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == latest_batch.first_event_id).first()
    first_evt.previous_chain_hash = "broken_link"
    db.commit()
    db.close()

    break_res = test_client.get(f"/api/v1/batches/{target_batch_id}")
    assert break_res.json()["chain_continuous"] is False

    stats_break_res = test_client.get("/api/v1/batches/stats")
    assert stats_break_res.json()["overall_chain_continuous"] is False
