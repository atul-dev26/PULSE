import json
import os
from datetime import datetime

ANCHOR_LOG_FILE = "data/integrity/anchor_log.jsonl"
os.makedirs(os.path.dirname(ANCHOR_LOG_FILE), exist_ok=True)

def anchor_batch(batch_id: str, merkle_root: str, first_event_id: str, last_event_id: str, event_count: int, fake_tx_id: str):
    """
    Simulates anchoring the batch to a blockchain like Hyperledger Fabric.
    In a real production environment, this function would wrap a gRPC or REST call to
    a Fabric chaincode (e.g., AnchorBatch API) which persists the Merkle root onto the ledger
    where it becomes immutable. Here in the MVP, we just append to a local JSONL file.
    """
    record = {
        "batch_id": batch_id,
        "merkle_root": merkle_root,
        "first_event_id": first_event_id,
        "last_event_id": last_event_id,
        "event_count": event_count,
        "timestamp": datetime.utcnow().isoformat(),
        "fake_tx_id": fake_tx_id
    }
    
    with open(ANCHOR_LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
