from sqlalchemy import Column, String, DateTime, LargeBinary, Integer, JSON
from sqlalchemy.orm import declarative_base
from datetime import datetime
from .database import Base

class DLQRecordRow(Base):
    __tablename__ = "dlq_records"
    
    event_id = Column(String, primary_key=True, index=True)
    raw_sha256 = Column(String)
    failure_stage = Column(String)
    error_code = Column(String)
    error_message = Column(String)
    attempt = Column(Integer, default=1)
    timestamp = Column(DateTime, default=datetime.utcnow)

class RawEventRow(Base):
    __tablename__ = "raw_events"
    
    event_id = Column(String, primary_key=True, index=True)
    source_id = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    transport = Column(String)
    payload = Column(LargeBinary)
    raw_sha256 = Column(String)
    storage_uri = Column(String)

class CanonicalEventRow(Base):
    __tablename__ = "canonical_events"
    
    event_id = Column(String, primary_key=True, index=True)
    timestamp = Column(String)
    source = Column(JSON)
    network = Column(JSON)
    security = Column(JSON)
    provenance = Column(JSON)
    enrichment = Column(JSON, nullable=True)

class IntegrityRecordRow(Base):
    __tablename__ = "integrity_records"
    
    seq_id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, index=True, unique=True)
    raw_hash = Column(String)
    normalized_hash = Column(String)
    parser_id = Column(String)
    parser_version = Column(String)
    mapping_version = Column(String)
    processed_at = Column(DateTime, default=datetime.utcnow)
    previous_chain_hash = Column(String)
    chain_hash = Column(String)
    batch_id = Column(String, nullable=True)

class BatchRow(Base):
    __tablename__ = "batches"
    
    batch_id = Column(String, primary_key=True)
    merkle_root = Column(String)
    first_event_id = Column(String)
    last_event_id = Column(String)
    event_count = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    fake_tx_id = Column(String)
