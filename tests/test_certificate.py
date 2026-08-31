import pytest
import os
import json
import hashlib

def _ingest(client, i=0):
    res = client.post("/api/v1/ingest", json={
        "source_id": f"cert-src-{i}",
        "transport": "HTTP",
        "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
    })
    return res.json()["event_id"]

class TestCertificateCleanBatched:
    def test_clean_batched_certificate(self, test_client):
        # Trigger batching
        event_ids = [_ingest(test_client, i) for i in range(500, 503)]
        eid = event_ids[0]
        
        res = test_client.get(f"/api/v1/events/{eid}/custody-certificate")
        assert res.status_code == 200
        data = res.json()
        
        assert data["event_id"] == eid
        assert data["verification_result"]["overall"] == "VERIFIED"
        assert data["chain_of_custody"]["merkle_batch_id"] is not None
        assert data["chain_of_custody"]["anchor_reference"] is not None
        assert data["trust_score"]["score"] >= 90
        
        # Verify certificate hash logic
        cert_hash = data.pop("certificate_hash")
        cert_json = json.dumps(data, separators=(',', ':'), sort_keys=True)
        expected_hash = hashlib.sha256(cert_json.encode("utf-8")).hexdigest()
        assert cert_hash == expected_hash

class TestCertificateTampered:
    def test_tampered_certificate(self, test_client):
        eid = _ingest(test_client, 600)
        
        raw_path = os.path.join("raw", f"{eid}.raw")
        with open(raw_path, "wb") as f:
            f.write(b'{"src": "TAMPERED", "dest": "10.0.0.99", "action": "allow"}')
            
        res = test_client.get(f"/api/v1/events/{eid}/custody-certificate")
        assert res.status_code == 200
        data = res.json()
        
        assert data["verification_result"]["overall"] == "TAMPERING_DETECTED"
        assert data["verification_result"]["raw_integrity"] is False
        assert data["trust_score"]["score"] < 20

class TestCertificateUnbatched:
    def test_unbatched_certificate(self, test_client):
        eid = _ingest(test_client, 700)
        
        res = test_client.get(f"/api/v1/events/{eid}/custody-certificate")
        assert res.status_code == 200
        data = res.json()
        
        assert data["verification_result"]["overall"] == "VERIFIED_PENDING_BATCH"
        assert data["chain_of_custody"]["merkle_batch_id"] is None
        assert data["chain_of_custody"]["merkle_root"] is None
        assert data["chain_of_custody"]["anchor_reference"] is None
