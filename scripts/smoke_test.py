"""Minimal smoke test for the ULPF REST API — run from the project root."""
import urllib.request
import json
import sys

BASE = "http://localhost:8000"

def get(path):
    r = urllib.request.urlopen(BASE + path)
    return json.loads(r.read())

def post(path):
    req = urllib.request.Request(BASE + path, method="POST")
    r = urllib.request.urlopen(req)
    return json.loads(r.read())

# 1. Stats
stats = get("/api/v1/stats")
print("=== /api/v1/stats ===")
print(json.dumps(stats, indent=2))

# 2. Events list
events = get("/api/v1/events?limit=3")
print(f"\n=== /api/v1/events (got {len(events)} events) ===")
for e in events:
    print(f"  {e['event_id'][:12]}... parser={e.get('parser_id')} action={e.get('action')}")

# 3. POST verify on first event
if events:
    eid = events[0]["event_id"]
    result = post(f"/api/v1/events/{eid}/verify")
    print(f"\n=== POST /api/v1/events/{eid[:12]}.../verify ===")
    print(json.dumps(result, indent=2))
    assert result["overall"] in ("VERIFIED", "TAMPERING_DETECTED"), "Unexpected overall value"
    print(f"\nVerification result: {result['overall']}")
else:
    print("\nNo events to verify — ingest some logs first.")

print("\nAll smoke tests passed!")
