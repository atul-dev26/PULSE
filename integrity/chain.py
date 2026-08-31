import hashlib
import json
from sqlalchemy.orm import Session
from common.models import IntegrityRecordRow
from datetime import datetime

GENESIS_HASH = hashlib.sha256(b"ULPF_GENESIS").hexdigest()

def compute_normalized_hash(canonical_dict: dict) -> str:
    # Convert to json with sorted keys and no spaces
    json_str = json.dumps(canonical_dict, separators=(',', ':'), sort_keys=True)
    return hashlib.sha256(json_str.encode('utf-8')).hexdigest()

def append_to_chain(db: Session, event_id: str, raw_hash: str, canonical_dict: dict, parser_id: str, parser_version: str, mapping_version: str):
    normalized_hash = compute_normalized_hash(canonical_dict)
    
    # Needs a DB lock in production (e.g., SELECT ... FOR UPDATE),
    # but SQLite sequential thread operations are adequate for MVP demo.
    last_record = db.query(IntegrityRecordRow).order_by(IntegrityRecordRow.seq_id.desc()).first()
    previous_chain_hash = last_record.chain_hash if last_record else GENESIS_HASH
    
    # Compute new chain hash
    data_to_hash = event_id + raw_hash + normalized_hash + parser_version + mapping_version + previous_chain_hash
    chain_hash = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()
    
    record = IntegrityRecordRow(
        event_id=event_id,
        raw_hash=raw_hash,
        normalized_hash=normalized_hash,
        parser_id=parser_id,
        parser_version=parser_version,
        mapping_version=mapping_version,
        processed_at=datetime.utcnow(),
        previous_chain_hash=previous_chain_hash,
        chain_hash=chain_hash,
        batch_id=None
    )
    
    db.add(record)
    db.flush()  # Flush so the record is visible to subsequent queries (e.g. check_and_create_batch)
    # We leave the caller to db.commit() to ensure atomicity.
