"""Tests for POST /api/v1/events/{event_id}/verify with unknown-format events.

An 'unknown format' event is one whose raw payload couldn't be parsed into any
known format (JSON / Syslog / CEF).  The ingestion pipeline stores it as raw
evidence with a sha-256 fingerprint but never creates an IntegrityRecord or a
CanonicalEvent for it.

The verify endpoint MUST:
  - Return HTTP 200 (not 404)
  - Set overall = 'NOT_APPLICABLE'
  - Still report raw_integrity (True when the file is untouched)
  - Set normalized_integrity, chain_integrity, merkle_integrity to None
  - Include a human-readable 'reason' field

It MUST also:
  - Return HTTP 404 for a completely unknown event_id that was never ingested.
"""


def test_verify_unknown_format_event_returns_200_not_applicable(test_client):
    """Ingest a plaintext payload (unknown format) then call POST verify."""
    unknown_payload = "??@@!!###***==="

    # 1. Ingest — expect accepted with format=unknown
    ingest_resp = test_client.post("/api/v1/ingest", json={
        "source_id": "test-unknown-src",
        "transport": "file",
        "payload": unknown_payload
    })
    assert ingest_resp.status_code == 200, ingest_resp.text
    ingest_data = ingest_resp.json()
    assert ingest_data["status"] == "accepted"
    assert ingest_data.get("format") == "unknown", (
        f"Expected format='unknown', got {ingest_data.get('format')!r}. "
        "If the payload was detected as a known format, choose a different payload."
    )
    event_id = ingest_data["event_id"]

    # 2. POST verify — must NOT be a 404
    verify_resp = test_client.post(f"/api/v1/events/{event_id}/verify")
    assert verify_resp.status_code == 200, (
        f"Expected 200 for unknown-format event, got {verify_resp.status_code}: {verify_resp.text}"
    )

    d = verify_resp.json()

    # overall must be NOT_APPLICABLE
    assert d["overall"] == "NOT_APPLICABLE", f"overall={d['overall']!r}"

    # raw_integrity must be a bool (True when file is intact, which it is)
    assert isinstance(d["raw_integrity"], bool), f"raw_integrity should be bool, got {type(d['raw_integrity'])}"
    assert d["raw_integrity"] is True, "raw file was just written — should be intact"

    # chain / normalized / merkle must all be None
    assert d["normalized_integrity"] is None, f"normalized_integrity should be None, got {d['normalized_integrity']!r}"
    assert d["chain_integrity"] is None, f"chain_integrity should be None, got {d['chain_integrity']!r}"
    assert d["merkle_integrity"] is None, f"merkle_integrity should be None, got {d['merkle_integrity']!r}"

    # reason must be a non-empty string
    assert isinstance(d.get("reason"), str) and d["reason"], "Expected a non-empty 'reason' string"


def test_verify_completely_unknown_event_id_returns_404(test_client):
    """A random event_id that was never ingested should still return 404."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = test_client.post(f"/api/v1/events/{fake_id}/verify")
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"
