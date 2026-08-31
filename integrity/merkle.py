import hashlib
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from common.models import IntegrityRecordRow, BatchRow
from .anchor import anchor_batch

def compute_merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return ""
    if len(hashes) == 1:
        return hashes[0]
        
    next_level = []
    for i in range(0, len(hashes), 2):
        left = hashes[i]
        right = hashes[i+1] if i+1 < len(hashes) else left
        combined = left + right
        next_level.append(hashlib.sha256(combined.encode('utf-8')).hexdigest())
    
    return compute_merkle_root(next_level)

def check_and_create_batch(db: Session, batch_size: int = 10):
    unbatched = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.batch_id == None).order_by(IntegrityRecordRow.seq_id.asc()).all()
    
    if len(unbatched) >= batch_size:
        # Create a batch
        target_records = unbatched[:batch_size]
        hashes = [r.chain_hash for r in target_records]
        merkle_root = compute_merkle_root(hashes)
        
        batch_id = str(uuid.uuid4())
        fake_tx_id = str(uuid.uuid4())
        
        first_event_id = target_records[0].event_id
        last_event_id = target_records[-1].event_id
        
        batch_record = BatchRow(
            batch_id=batch_id,
            merkle_root=merkle_root,
            first_event_id=first_event_id,
            last_event_id=last_event_id,
            event_count=len(target_records),
            created_at=datetime.utcnow(),
            fake_tx_id=fake_tx_id
        )
        db.add(batch_record)
        
        for r in target_records:
            r.batch_id = batch_id
            
        anchor_batch(batch_id, merkle_root, first_event_id, last_event_id, len(target_records), fake_tx_id)
        # Assuming db.commit() happens downstream
