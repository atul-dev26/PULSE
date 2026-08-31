import json

def parse_json(payload_bytes: bytes) -> dict:
    return json.loads(payload_bytes.decode('utf-8'))
