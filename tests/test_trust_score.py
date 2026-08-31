"""
Tests for the Evidence Trust Score feature.

Four scenarios:
1. Clean, fully-batched event → score 90+
2. Fresh, unbatched event → merkle/anchor excluded, still reasonably high
3. Tampered raw evidence → score < 20, raw_hash_failure_0.15x penalty
4. Raw intact but schema_validated fails → schema_failure_0.55x penalty
"""

import pytest
import os


def _ingest(client, i=0):
    """Helper: ingest a JSON event and return event_id."""
    res = client.post("/api/v1/ingest", json={
        "source_id": f"trust-src-{i}",
        "transport": "HTTP",
        "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "accepted"
    return data["event_id"]


class TestTrustScoreCleanBatched:
    """Scenario 1: Fully-batched, untampered event → high score (90+)."""

    def test_high_score_for_clean_batch(self, test_client):
        # Ingest 3 events to trigger Merkle batching (batch_size=3)
        event_ids = [_ingest(test_client, i) for i in range(100, 103)]

        # Check trust score for each batched event
        for eid in event_ids:
            res = test_client.get(f"/api/v1/events/{eid}/trust-score")
            assert res.status_code == 200
            data = res.json()

            assert data["event_id"] == eid
            assert data["trust_score"] >= 90
            assert data["score_breakdown"]["penalty_applied"] == "none"
            assert data["tampering_detected"] is False
            # All checks should have passed (no None / excluded items)
            assert data["score_breakdown"]["excluded_pending_items"] == []
            # Verify all core checks passed
            for check in data["checks"]:
                if check["label"] != "Threat intelligence available":
                    assert check["passed"] is True, f"{check['label']} should pass"


class TestTrustScoreUnbatched:
    """Scenario 2: Fresh event not yet batched → merkle/anchor excluded,
    score still reasonably high."""

    def test_unbatched_event_not_penalized(self, test_client):
        # Ingest just 1 event (won't trigger batch_size=3 threshold)
        eid = _ingest(test_client, 200)

        res = test_client.get(f"/api/v1/events/{eid}/trust-score")
        assert res.status_code == 200
        data = res.json()

        assert data["event_id"] == eid
        # Merkle + blockchain should be excluded, not penalized
        excluded = data["score_breakdown"]["excluded_pending_items"]
        assert "merkle_proof_verified" in excluded
        assert "blockchain_anchor_verified" in excluded

        # Score should still be high because all *applicable* checks pass
        assert data["trust_score"] >= 80
        assert data["score_breakdown"]["penalty_applied"] == "none"
        assert data["tampering_detected"] is False

        # Verify checks show None for excluded items
        for check in data["checks"]:
            if check["label"] in ("Merkle proof verified", "Blockchain anchor verified"):
                assert check["passed"] is None
                assert "Excluded" in check.get("note", "")


class TestTrustScoreRawTampered:
    """Scenario 3: Raw evidence tampered → score < 20, penalty = raw_hash_failure_0.15x."""

    def test_tampered_raw_drops_score(self, test_client):
        eid = _ingest(test_client, 300)

        # Confirm clean score first
        res = test_client.get(f"/api/v1/events/{eid}/trust-score")
        assert res.status_code == 200
        clean_score = res.json()["trust_score"]
        assert clean_score >= 80

        # Tamper with the raw file on disk
        raw_path = os.path.join("raw", f"{eid}.raw")
        with open(raw_path, "wb") as f:
            f.write(b'{"src": "TAMPERED", "dest": "10.0.0.99", "action": "allow"}')

        # Re-check trust score
        res2 = test_client.get(f"/api/v1/events/{eid}/trust-score")
        assert res2.status_code == 200
        data = res2.json()

        assert data["trust_score"] < 20
        assert data["score_breakdown"]["penalty_applied"] == "raw_hash_failure_0.15x"
        assert data["tampering_detected"] is True


class TestTrustScoreSchemaFailure:
    """Scenario 4: Raw intact but schema_validated fails → schema_failure_0.55x penalty,
    score lands in a moderate-low range between clean and fully-tampered."""

    def test_schema_failure_moderate_penalty(self, test_client):
        eid = _ingest(test_client, 400)

        # Confirm clean score first
        res = test_client.get(f"/api/v1/events/{eid}/trust-score")
        assert res.status_code == 200
        clean_score = res.json()["trust_score"]
        assert clean_score >= 80

        # Tamper with the canonical record in the DB (simulating post-ingestion
        # modification of the normalized data while leaving raw intact)
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from common.models import CanonicalEventRow

        engine = create_engine("sqlite:///./test_ulpf.db",
                               connect_args={"check_same_thread": False})
        Session = sessionmaker(bind=engine)
        db = Session()
        try:
            canonical = db.query(CanonicalEventRow).filter(
                CanonicalEventRow.event_id == eid
            ).first()
            assert canonical is not None
            # Modify the network field to break the normalized hash
            net = canonical.network.copy() if canonical.network else {}
            net["source_ip"] = "TAMPERED_IP"
            canonical.network = net
            db.commit()
        finally:
            db.close()

        # Re-check trust score
        res2 = test_client.get(f"/api/v1/events/{eid}/trust-score")
        assert res2.status_code == 200
        data = res2.json()

        assert data["score_breakdown"]["penalty_applied"] == "schema_failure_0.55x"
        # Score should be moderate-low: distinctly between clean (90+) and
        # fully-tampered (< 20)
        assert 20 <= data["trust_score"] <= 65
        assert data["tampering_detected"] is True

        # Also verify trace endpoint includes trust score
        trace_res = test_client.get(f"/api/v1/events/{eid}/trace")
        assert trace_res.status_code == 200
        trace_data = trace_res.json()
        assert "trust_score" in trace_data
        assert "score_breakdown" in trace_data
