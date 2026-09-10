import uuid
import hashlib
import os
from datetime import datetime
from sqlalchemy.orm import Session

from common.models import RawEventRow, CanonicalEventRow, DLQRecordRow
from parser.json_parser import parse_json
from parser.syslog_parser import parse_syslog
from parser.cef_parser import parse_cef
from parser.leef_parser import parse_leef
from parser.drain3_parser import parse_drain3
from normalization.json_mapper import map_to_canonical
from detection.detector import detect
from integrity.chain import append_to_chain
from integrity.merkle import check_and_create_batch
from correlation.engine import run_correlation
from enrichment import ENRICHMENT_CONFIG
from enrichment.ip_classifier import classify_ip
from enrichment.geoip import get_country_code
from normalization.schema import EventEnrichment
from observability.metrics import (
    EVENTS_RECEIVED, 
    EVENTS_PARSED, 
    EVENTS_FAILED, 
    PARSE_LATENCY, 
    update_eps
)
import time
from onboarding.models import PendingSourceRow
from onboarding.discovery import discover_fields
from onboarding.inference import infer_mappings

RAW_STORAGE_DIR = "data/raw"
# Create raw dir in the same directory as this script execution (ulpf)
os.makedirs(RAW_STORAGE_DIR, exist_ok=True)

def process_ingestion(db: Session, source_id: str, transport: str, payload_str: str) -> dict:
    EVENTS_RECEIVED.inc()
    update_eps()
    
    event_id = str(uuid.uuid4())
    payload_bytes = payload_str.encode('utf-8')
    raw_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    
    # Run format detector
    detection = detect(payload_bytes)
    
    storage_uri = os.path.join(RAW_STORAGE_DIR, f"{event_id}.raw")
    
    # 1. Write the exact raw payload to file
    with open(storage_uri, "wb") as f:
        f.write(payload_bytes)
        
    # 2. Store RawEvent metadata
    raw_event = RawEventRow(
        event_id=event_id,
        source_id=source_id,
        received_at=datetime.utcnow(),
        transport=transport,
        payload=payload_bytes,
        raw_sha256=raw_sha256,
        storage_uri=storage_uri
    )
    db.add(raw_event)
    db.flush()
    
    res = {"event_id": event_id, "status": "accepted"}
    
    # Auto-onboarding logic
    pending_src = db.query(PendingSourceRow).filter_by(source_id=source_id).first()
    
    if detection.format in ("unknown", "drain3"):
        if pending_src and pending_src.status == "approved" and pending_src.approved_mapping:
            # Override detection and parsing
            detection.format = "auto_onboarded"
            detection.parser_id = "onboarding_parser"
        elif not pending_src:
            fields = discover_fields(payload_str)
            if fields:
                suggestions = infer_mappings(fields)
                pending_src = PendingSourceRow(
                    source_id=source_id,
                    sample_payload=payload_str,
                    discovered_fields=fields,
                    suggested_mapping=suggestions,
                    status="pending"
                )
            else:
                pending_src = PendingSourceRow(
                    source_id=source_id,
                    sample_payload=payload_str,
                    discovered_fields={},
                    suggested_mapping={},
                    status="rejected"  # not eligible
                )
            db.add(pending_src)
            db.flush()
            # Leave detection alone so it flows to drain3/unknown for now

    if detection.format == "unknown":
        db.commit()
        res["format"] = "unknown"
        res["note"] = "stored raw, not parsed"
        return res
        
    res["format"] = detection.format
    
    # 3. Parse and Map
    stage = "parsing"
    start_time = time.time()
    try:
        parsed_data = None
        if detection.parser_id == "json_parser":
            parsed_data = parse_json(payload_bytes)
        elif detection.parser_id == "syslog_parser":
            parsed_data = parse_syslog(payload_bytes)
        elif detection.parser_id == "cef_parser":
            parsed_data = parse_cef(payload_bytes)
        elif detection.parser_id == "leef_parser":
            parsed_data = parse_leef(payload_bytes)
        elif detection.parser_id == "drain3_parser":
            parsed_data = parse_drain3(payload_bytes)
        elif detection.parser_id == "onboarding_parser":
            fields = discover_fields(payload_str)
            parsed_data = {}
            for raw_k, raw_v in fields.items():
                parsed_data[raw_k] = raw_v
                # Transform using approved mapping
                if raw_k in pending_src.approved_mapping:
                    c_field = pending_src.approved_mapping[raw_k]["canonical_field"]
                    leaf = c_field.split(".")[-1]
                    parsed_data[leaf] = raw_v
            
        stage = "normalization"
        if parsed_data is not None:
            PARSE_LATENCY.observe(time.time() - start_time)
            EVENTS_PARSED.labels(format=detection.parser_id).inc()
            
            # 4. Map to Canonical
            canonical_model = map_to_canonical(event_id, parsed_data, parser_id=detection.parser_id)
            
            # Enrichment step
            enrichment_data = EventEnrichment()
            src_ip = canonical_model.network.source_ip
            dst_ip = canonical_model.network.destination_ip

            if ENRICHMENT_CONFIG.get("ip_classification"):
                if src_ip:
                    enrichment_data.source_ip_class = classify_ip(src_ip)
                if dst_ip:
                    enrichment_data.destination_ip_class = classify_ip(dst_ip)

            if ENRICHMENT_CONFIG.get("geoip"):
                if dst_ip and getattr(enrichment_data, "destination_ip_class", None) == "public":
                    enrichment_data.destination_geo_country = get_country_code(dst_ip)
                    
            canonical_model.enrichment = enrichment_data
            
            # 5. Store Canonical in DB
            canonical_row = CanonicalEventRow(
                event_id=canonical_model.event_id,
                timestamp=canonical_model.timestamp,
                source=canonical_model.source.model_dump(),
                network=canonical_model.network.model_dump(),
                security=canonical_model.security.model_dump(),
                provenance=canonical_model.provenance.model_dump(),
                enrichment=canonical_model.enrichment.model_dump()
            )
            db.add(canonical_row)
            db.flush()
            
            # 6. Integrity Layer
            # We construct a canonical dict as it would be serialized to JSON
            canonical_dict = {
                "event_id": canonical_model.event_id,
                "timestamp": canonical_model.timestamp,
                "source": canonical_model.source.model_dump(),
                "network": canonical_model.network.model_dump(),
                "security": canonical_model.security.model_dump(),
                "provenance": canonical_model.provenance.model_dump(),
                "enrichment": canonical_model.enrichment.model_dump()
            }
            append_to_chain(
                db=db,
                event_id=event_id,
                raw_hash=raw_sha256,
                canonical_dict=canonical_dict,
                parser_id=detection.parser_id,
                parser_version="1.0.0",
                mapping_version="1.0.0"
            )
            
            # 7. Merkle Batching
            check_and_create_batch(db, batch_size=3) # Use 3 for testing MVP efficiently
            
    except Exception as e:
        EVENTS_FAILED.inc()
        dlq_record = DLQRecordRow(
            event_id=event_id,
            raw_sha256=raw_sha256,
            failure_stage=stage,
            error_code=type(e).__name__,
            error_message=str(e),
            attempt=1
        )
        db.add(dlq_record)
        res["format"] = "unknown_or_failed"
        res["note"] = f"sent to DLQ, see /api/v1/dlq/{event_id}"
        
    db.commit()

    # ── Correlation Engine Hook ──────────────────────────────────────
    # Run lightweight rule-based correlation for the source_ip of the
    # just-ingested event.  Wrapped in try/except so correlation issues
    # never break the ingestion pipeline.
    try:
        corr_ip = None
        if 'canonical_model' in dir():
            # canonical_model is only set when parsing succeeded
            pass
        # We need to extract source_ip; easiest to re-derive from the
        # canonical row we just stored.
        corr_row = db.query(CanonicalEventRow).filter(
            CanonicalEventRow.event_id == event_id
        ).first()
        if corr_row and corr_row.network:
            corr_ip = corr_row.network.get("source_ip")
        if corr_ip:
            run_correlation(db, corr_ip)
    except Exception as e:
        # Never let correlation break ingestion
        print(f"[correlation] post-ingest error: {e}")

    return res

