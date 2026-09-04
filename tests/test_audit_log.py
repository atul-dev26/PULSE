"""Tests for access audit logging on forensic endpoints."""


def _ingest(test_client, payload_str, source_id="audit-test-src"):
    """Helper to ingest a single event and return its event_id."""
    resp = test_client.post("/api/v1/ingest", json={
        "source_id": source_id,
        "transport": "http",
        "payload": payload_str
    })
    assert resp.status_code == 200
    return resp.json()["event_id"]


class TestAuditLog:
    """Verify that forensic actions create AuditLogEntry records."""

    def test_verify_creates_audit_entry(self, test_client):
        """Calling POST /events/{id}/verify should create an audit log
        entry with action='verified_event' and the correct event_id."""

        # 1. Ingest an event so there is something to verify
        event_id = _ingest(test_client, '{"action": "audit-test", "src_ip": "10.0.0.1"}')

        # 2. Verify the event
        resp = test_client.post(f"/api/v1/events/{event_id}/verify")
        assert resp.status_code == 200

        # 3. Check the audit log for the entry
        audit_resp = test_client.get("/api/v1/audit?action=verified_event")
        assert audit_resp.status_code == 200
        audit_data = audit_resp.json()

        assert "entries" in audit_data
        assert "pagination" in audit_data

        # Find the entry matching our event_id
        matching = [e for e in audit_data["entries"] if e["event_id"] == event_id]
        assert len(matching) >= 1, f"Expected audit entry for event {event_id}, found none"

        entry = matching[0]
        assert entry["action"] == "verified_event"
        assert entry["event_id"] == event_id
        assert entry["username"] == "system"

    def test_audit_endpoint_pagination_shape(self, test_client):
        """GET /api/v1/audit should return entries and pagination metadata."""

        resp = test_client.get("/api/v1/audit?page=1&page_size=10")
        assert resp.status_code == 200
        data = resp.json()

        assert "entries" in data
        assert isinstance(data["entries"], list)

        pag = data["pagination"]
        assert "page" in pag
        assert "page_size" in pag
        assert "total_events" in pag
        assert "total_pages" in pag
        assert pag["page_size"] == 10

    def test_audit_filter_by_action(self, test_client):
        """Filtering by action should only return matching entries."""

        # Ingest + verify to ensure at least one 'verified_event' entry exists
        event_id = _ingest(test_client, '{"action": "filter-audit", "src_ip": "10.0.0.2"}')
        test_client.post(f"/api/v1/events/{event_id}/verify")

        resp = test_client.get("/api/v1/audit?action=verified_event")
        assert resp.status_code == 200
        data = resp.json()

        for entry in data["entries"]:
            assert entry["action"] == "verified_event"
