import requests
import json
import hashlib

API_URL = "http://127.0.0.1:8000/api/v1/ingest"
EVENT_URL = "http://127.0.0.1:8000/api/v1/events/"

def main():
    # Mix of firewall-deny, VPN-connect, and DNS-query style events
    # using different field-name variants for source IP.
    events = [
        {
            "event_type": "firewall-deny",
            "src": "192.168.1.100",
            "dest": "10.0.0.1",
            "action": "DROP"
        },
        {
            "event_type": "VPN-connect",
            "source_ip": "10.10.10.50",
            "user": "alice",
            "status": "SUCCESS"
        },
        {
            "event_type": "DNS-query",
            "sourceAddress": "172.16.0.55",
            "query": "example.com"
        },
        {
            "event_type": "firewall-deny",
            "src_ip": "192.168.2.20",
            "action": "BLOCK"
        },
        {
            "event_type": "VPN-connect",
            "src": "10.0.0.99",
            "user": "bob",
            "status": "FAILED"
        }
    ]

    results = []

    print("Posting logs to", API_URL, "...\n")

    for idx, event in enumerate(events):
        payload_str = json.dumps(event)
        req_body = {
            "source_id": f"demo-script-{idx}",
            "transport": "HTTP",
            "payload": payload_str
        }

        # Calculate expected raw_sha256
        payload_bytes = payload_str.encode("utf-8")
        raw_sha256 = hashlib.sha256(payload_bytes).hexdigest()

        try:
            # 1. Ingest the event
            resp = requests.post(API_URL, json=req_body)
            resp.raise_for_status()
            data = resp.json()
            event_id = data["event_id"]
            
            # 2. Fetch the canonical event to get the parsed source_ip
            ev_resp = requests.get(EVENT_URL + event_id)
            ev_resp.raise_for_status()
            ev_data = ev_resp.json()

            parsed_source_ip = ev_data.get("network", {}).get("source_ip", "N/A")
            
            results.append({
                "event_id": event_id,
                "source_ip": parsed_source_ip,
                "raw_sha256": raw_sha256
            })
        except Exception as e:
            print(f"Error processing {event}: {e}")

    # Print summary table
    print(f"{'event_id':<38} | {'parsed source_ip':<18} | {'raw_sha256'}")
    print("-" * 125)
    for r in results:
        print(f"{r['event_id']:<38} | {str(r['source_ip']):<18} | {r['raw_sha256']}")

if __name__ == "__main__":
    main()
