"""
Tests for the rule-based correlation engine.

Test 1: Feed 5 failed logins from the same IP → confirm Brute Force incident (T1110).
Test 2: Feed brute-force pattern + privilege escalation → confirm escalation (T1078).
"""
import json


def _make_failed_login_payload(source_ip: str, index: int) -> dict:
    """Helper: create a JSON log payload that will map to security.action = 'failed_login'."""
    return {
        "source_id": "test-correlation",
        "transport": "http",
        "payload": json.dumps({
            "timestamp": f"2026-09-07T00:{10 + index}:00",
            "hostname": "auth-server-01",
            "service": "sshd",
            "severity": "WARNING",
            "message": f"Failed password for admin attempt {index}",
            "source_ip": source_ip,
            "destination_ip": "10.0.0.10",
            "event_type": "failed_login",
        }),
    }


def _make_priv_esc_payload(source_ip: str) -> dict:
    """Helper: create a JSON log payload that maps to security.action = 'privilege_escalation'."""
    return {
        "source_id": "test-correlation",
        "transport": "http",
        "payload": json.dumps({
            "timestamp": "2026-09-07T00:20:00",
            "hostname": "auth-server-01",
            "service": "sudo",
            "severity": "WARNING",
            "message": "Privilege escalation attempt detected",
            "source_ip": source_ip,
            "destination_ip": "10.0.0.10",
            "event_type": "privilege_escalation",
        }),
    }


def test_brute_force_incident(test_client):
    """
    Ingest 5 failed_login events from the same IP.
    The correlation engine should create a T1110 (Brute Force) incident.
    """
    attacker_ip = "203.0.113.50"

    # Ingest 5 failed login events
    event_ids = []
    for i in range(5):
        resp = test_client.post(
            "/api/v1/ingest",
            json=_make_failed_login_payload(attacker_ip, i),
        )
        assert resp.status_code == 200, f"Ingest {i} failed: {resp.text}"
        data = resp.json()
        assert data["status"] == "accepted"
        event_ids.append(data["event_id"])

    # Query incidents
    resp = test_client.get("/api/v1/incidents", params={"status": "open"})
    assert resp.status_code == 200
    incidents_data = resp.json()

    # Find the T1110 incident for our attacker IP
    brute_force_incidents = [
        inc for inc in incidents_data["incidents"]
        if inc["technique"] == "T1110" and inc["source_ip"] == attacker_ip
    ]
    assert len(brute_force_incidents) >= 1, (
        f"Expected at least 1 T1110 incident for {attacker_ip}, "
        f"got {len(brute_force_incidents)}. All incidents: {incidents_data}"
    )

    bf = brute_force_incidents[0]
    assert bf["severity"] == "high"
    assert bf["status"] == "open"
    assert len(bf["event_ids"]) >= 5

    # Verify detail endpoint
    detail_resp = test_client.get(f"/api/v1/incidents/{bf['incident_id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["technique"] == "T1110"
    assert len(detail["contributing_events"]) >= 5


def test_privilege_escalation_chain(test_client):
    """
    Ingest 5 failed logins (trigger brute force), then ingest a
    privilege_escalation event from the same IP.
    The engine should create a T1078 (Valid Accounts) incident.
    """
    attacker_ip = "198.51.100.99"

    # Step 1: Ingest 5 failed logins to trigger brute-force
    for i in range(5):
        resp = test_client.post(
            "/api/v1/ingest",
            json=_make_failed_login_payload(attacker_ip, i),
        )
        assert resp.status_code == 200

    # Confirm brute-force incident exists
    resp = test_client.get("/api/v1/incidents", params={"status": "open"})
    assert resp.status_code == 200
    bf_incidents = [
        inc for inc in resp.json()["incidents"]
        if inc["technique"] == "T1110" and inc["source_ip"] == attacker_ip
    ]
    assert len(bf_incidents) >= 1, f"Brute-force incident not found: {resp.json()}"

    # Step 2: Ingest a privilege escalation event from the same IP
    resp = test_client.post(
        "/api/v1/ingest",
        json=_make_priv_esc_payload(attacker_ip),
    )
    assert resp.status_code == 200

    # Check for the escalated T1078 incident
    resp = test_client.get("/api/v1/incidents", params={"status": "open"})
    assert resp.status_code == 200
    esc_incidents = [
        inc for inc in resp.json()["incidents"]
        if inc["technique"] == "T1078" and inc["source_ip"] == attacker_ip
    ]
    assert len(esc_incidents) >= 1, (
        f"Expected T1078 escalation incident for {attacker_ip}, "
        f"got: {resp.json()}"
    )

    esc = esc_incidents[0]
    assert esc["severity"] == "critical"
    assert esc["status"] == "open"
    # Should include the 5 brute-force event_ids + the priv-esc event
    assert len(esc["event_ids"]) >= 6

    # Verify detail endpoint returns contributing events in order
    detail = test_client.get(f"/api/v1/incidents/{esc['incident_id']}").json()
    assert len(detail["contributing_events"]) >= 6
