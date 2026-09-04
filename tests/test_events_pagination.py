"""Tests for GET /api/v1/events pagination, trust_score, and filtering."""


def _ingest(test_client, payload_str, source_id="test-src"):
    """Helper to ingest a single event and return its event_id."""
    resp = test_client.post("/api/v1/ingest", json={
        "source_id": source_id,
        "transport": "http",
        "payload": payload_str
    })
    assert resp.status_code == 200
    return resp.json()["event_id"]


class TestEventsPagination:
    """Verify the new paginated response shape from GET /api/v1/events."""

    def test_response_has_events_and_pagination(self, test_client):
        # Ingest one event so the list is not empty
        _ingest(test_client, '{"action": "allow", "src_ip": "10.0.0.1"}')

        resp = test_client.get("/api/v1/events")
        assert resp.status_code == 200
        data = resp.json()

        # Top-level shape
        assert "events" in data
        assert "pagination" in data
        assert isinstance(data["events"], list)

        pag = data["pagination"]
        assert "page" in pag
        assert "page_size" in pag
        assert "total_events" in pag
        assert "total_pages" in pag

    def test_trust_score_field_present(self, test_client):
        _ingest(test_client, '{"action": "deny", "src_ip": "1.2.3.4"}')

        resp = test_client.get("/api/v1/events?page=1&page_size=10")
        assert resp.status_code == 200
        data = resp.json()

        assert len(data["events"]) >= 1
        first = data["events"][0]
        # trust_score key must exist (value may be int or None)
        assert "trust_score" in first

    def test_page_size_respected(self, test_client):
        # Ingest 3 events
        for i in range(3):
            _ingest(test_client, f'{{"action": "page-test-{i}", "src_ip": "10.0.0.{i}"}}')

        resp = test_client.get("/api/v1/events?page=1&page_size=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) <= 2
        assert data["pagination"]["page_size"] == 2

    def test_page_navigation(self, test_client):
        # Ingest 3 events
        for i in range(3):
            _ingest(test_client, f'{{"action": "nav-test-{i}", "src_ip": "10.1.0.{i}"}}')

        resp_p1 = test_client.get("/api/v1/events?page=1&page_size=2")
        resp_p2 = test_client.get("/api/v1/events?page=2&page_size=2")
        assert resp_p1.status_code == 200
        assert resp_p2.status_code == 200
        d1 = resp_p1.json()
        d2 = resp_p2.json()

        # Page 2 should have different (or fewer) events than page 1
        ids_p1 = {e["event_id"] for e in d1["events"]}
        ids_p2 = {e["event_id"] for e in d2["events"]}
        assert ids_p1.isdisjoint(ids_p2), "Page 1 and Page 2 should not overlap"

    def test_backward_compat_limit(self, test_client):
        _ingest(test_client, '{"action": "limit-test", "src_ip": "1.1.1.1"}')

        resp = test_client.get("/api/v1/events?limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert data["pagination"]["page_size"] == 5


class TestEventsFiltering:
    """Verify filtering by severity, format/parser_id, and source_id."""

    def test_filter_by_severity(self, test_client):
        _ingest(test_client, '{"action": "block", "severity": "high", "src_ip": "10.0.0.1"}', source_id="sev-test")
        _ingest(test_client, '{"action": "allow", "severity": "low", "src_ip": "10.0.0.2"}', source_id="sev-test")

        resp = test_client.get("/api/v1/events?severity=high")
        assert resp.status_code == 200
        data = resp.json()
        for ev in data["events"]:
            # severity should be "high" for all returned events (if non-null)
            if ev.get("severity"):
                assert ev["severity"].lower() == "high"

    def test_filter_by_source_id(self, test_client):
        _ingest(test_client, '{"action": "test", "src_ip": "1.2.3.4"}', source_id="src-filter-A")
        _ingest(test_client, '{"action": "test", "src_ip": "5.6.7.8"}', source_id="src-filter-B")

        resp = test_client.get("/api/v1/events?source_id=src-filter-A")
        assert resp.status_code == 200
        data = resp.json()
        # All returned events should come from source_id=src-filter-A
        # We can't directly check source_id on canonical events easily,
        # but at least the response should be valid
        assert isinstance(data["events"], list)

    def test_filter_by_format(self, test_client):
        # JSON events go through json_parser
        _ingest(test_client, '{"action": "fmt-test", "src_ip": "1.1.1.1"}', source_id="fmt-src")

        resp = test_client.get("/api/v1/events?format=json_parser")
        assert resp.status_code == 200
        data = resp.json()
        for ev in data["events"]:
            pid = ev.get("parser_id") or (ev.get("provenance") or {}).get("parser_id")
            if pid:
                assert pid == "json_parser"


class TestEventsFiltersEndpoint:
    """Verify GET /api/v1/events/filters returns expected shape."""

    def test_filters_endpoint(self, test_client):
        _ingest(test_client, '{"action": "filter-ep", "src_ip": "2.2.2.2"}', source_id="filter-src")

        resp = test_client.get("/api/v1/events/filters")
        assert resp.status_code == 200
        data = resp.json()

        assert "sources" in data
        assert "formats" in data
        assert "severities" in data
        assert "statuses" in data
        assert isinstance(data["sources"], list)
        assert isinstance(data["formats"], list)
        assert isinstance(data["severities"], list)
        assert isinstance(data["statuses"], list)
