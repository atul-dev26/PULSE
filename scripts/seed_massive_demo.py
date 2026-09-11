import requests
import json
import random

API_URL = "https://pulse-production-7c5a.up.railway.app/api/v1/ingest"
LOGIN_URL = "https://pulse-production-7c5a.up.railway.app/api/v1/auth/login"

def get_token():
    try:
        resp = requests.post(LOGIN_URL, json={"username": "admin", "password": "changeme123"})
        resp.raise_for_status()
        return resp.json()["access_token"]
    except Exception as e:
        print("Failed to get token:", e)
        exit(1)

def generate_valid_json():
    ips = [f"192.168.1.{random.randint(1, 254)}", f"10.0.0.{random.randint(1, 254)}"]
    users = ["alice", "bob", "charlie", "admin", "guest"]
    actions = ["DROP", "BLOCK", "ALLOW", "SUCCESS", "FAILED"]
    events = [
        {"event_type": "firewall", "src_ip": random.choice(ips), "dest_ip": random.choice(ips), "action": random.choice(actions), "src_port": random.randint(1024, 65535), "dest_port": 80, "severity": "high"},
        {"event_type": "VPN", "source_ip": random.choice(ips), "user": random.choice(users), "status": random.choice(["SUCCESS", "FAILED"]), "severity": "medium"},
        {"event_type": "DNS", "sourceAddress": random.choice(ips), "query": "example.com", "severity": "low"}
    ]
    return random.choice(events)

def generate_cef():
    ips = [f"172.16.0.{random.randint(1, 254)}", f"10.10.10.{random.randint(1, 254)}"]
    return f"CEF:0|Security|ThreatManager|1.0|100|Malware Detected|8|src={random.choice(ips)} dst={random.choice(ips)} spt={random.randint(1024, 65535)} dpt=443 act=blocked"

def generate_syslog():
    ips = [f"192.168.100.{random.randint(1, 254)}", f"10.100.100.{random.randint(1, 254)}"]
    return f"<34>Oct 11 22:14:15 myfirewall kernel: DROP TCP {random.choice(ips)} -> {random.choice(ips)}:80"

def generate_unknown():
    users = ["admin", "root", "dev"]
    return f"custom_app_log user={random.choice(users)} action=login ip=10.10.10.{random.randint(1, 254)} status=success reason=auth_ok session_id={random.randint(1000, 9999)}"

def generate_dlq():
    # This will throw ValueError when int(source_port) is called
    ips = [f"192.168.1.{random.randint(1, 254)}"]
    return {"event_type": "firewall", "src_ip": random.choice(ips), "dest_ip": "1.1.1.1", "action": "DROP", "src_port": "not-a-number", "severity": "high"}

def post_event(payload, source_id, headers):
    req_body = {
        "source_id": source_id,
        "transport": "HTTP",
        "payload": payload
    }
    try:
        resp = requests.post(API_URL, json=req_body, headers=headers)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error posting event: {e}")

def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"Starting massive data generation targeting {API_URL}")
    
    # Generate 150 valid JSON
    for i in range(150):
        post_event(generate_valid_json(), f"json-source-{i%5}", headers)
        
    print("Injected 150 valid JSON logs")

    # Generate 30 CEF logs
    for i in range(30):
        post_event(generate_cef(), "cef-source-1", headers)

    print("Injected 30 CEF logs")

    # Generate 30 Syslog logs
    for i in range(30):
        post_event(generate_syslog(), "syslog-source-1", headers)
        
    print("Injected 30 Syslog logs")

    # Generate 20 unknown logs for Onboarding (DDL) page
    for i in range(20):
        post_event(generate_unknown(), f"custom-app-source-new-{i}", headers)
        
    print("Injected 20 unknown logs (for onboarding)")

    # Generate 20 DLQ logs
    for i in range(20):
        post_event(generate_dlq(), "buggy-source-1", headers)
        
    print("Injected 20 DLQ logs")
    print("Done generating demo data.")

if __name__ == "__main__":
    main()
