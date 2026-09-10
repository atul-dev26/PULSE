from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
import os

from common.database import get_db
from common.models import RawEventRow, CanonicalEventRow, IntegrityRecordRow, BatchRow, DLQRecordRow, AuditLogEntry
from ingestion.service import process_ingestion
from ingestion.splitter import split_payload
from observability.metrics import generate_latest, CONTENT_TYPE_LATEST, get_observability_json
from onboarding.models import PendingSourceRow
from auth.dependencies import get_current_user

router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/metrics")
def metrics():
    data = generate_latest()
    return Response(data, media_type=CONTENT_TYPE_LATEST)

@router.get("/api/v1/observability")
def observability():
    return get_observability_json()

from typing import Any, Union, Dict, List, Optional
from fastapi import Body, APIRouter, Depends, HTTPException, Request
from datetime import datetime

# ── Audit Logging Helper ────────────────────────────────────────────
def _log_audit(db: Session, request: Request, action: str, event_id: str = None, source_id: str = None):
    """Write a lightweight audit log entry after a successful action."""
    entry = AuditLogEntry(
        username="system",  # placeholder until JWT auth is implemented
        action=action,
        event_id=event_id,
        source_id=source_id,
        ip_address=request.client.host if request.client else None,
    )
    db.add(entry)
    db.commit()

@router.post("/api/v1/ingest")
def ingest(
    payload_body: Any = Body(
        default=None, 
        description="Payload can be any JSON object, list, or a raw string log (ensure raw strings are quoted)."
    ),
    source_id: str = "http_endpoint",
    transport: str = "http",
    db: Session = Depends(get_db)
):
    if not payload_body:
         raise HTTPException(status_code=400, detail="Empty payload")

    # If the user wrapped it in the old format intentionally
    if isinstance(payload_body, dict) and "payload" in payload_body:
        source_id = payload_body.get("source_id", source_id)
        transport = payload_body.get("transport", transport)
        p = payload_body["payload"]
        body_str = json.dumps(p) if isinstance(p, (dict, list)) else str(p)
    else:
        body_str = json.dumps(payload_body) if isinstance(payload_body, (dict, list)) else str(payload_body)

    splits = split_payload(body_str)
    
    if len(splits) == 1:
        return process_ingestion(db, source_id, transport, splits[0])
        
    results = []
    for item in splits:
        res = process_ingestion(db, source_id, transport, item)
        results.append(res)
        
    return {
        "batch": True,
        "total_logs_detected": len(splits),
        "results": results
    }

@router.get("/api/v1/events")
def list_events(
    page: int = 1,
    page_size: int = 25,
    limit: int = 50,
    source_id: str = None,
    format: str = None,
    severity: str = None,
    status: str = None,
    search: str = None,
    last_24h: bool = False,
    db: Session = Depends(get_db)
):
    from sqlalchemy import func
    from common.models import RawEventRow, CanonicalEventRow, DLQRecordRow
    
    # Cap page_size to 100
    if page_size > 100:
        page_size = 100
        
    if limit != 50 and page_size == 25:
        page_size = min(limit, 100)

    offset = (page - 1) * page_size

    # Build query joining raw, canonical, and dlq
    query = db.query(RawEventRow, CanonicalEventRow, DLQRecordRow)\
        .outerjoin(CanonicalEventRow, RawEventRow.event_id == CanonicalEventRow.event_id)\
        .outerjoin(DLQRecordRow, RawEventRow.event_id == DLQRecordRow.event_id)
    
    # filtering
    if source_id:
        query = query.filter(RawEventRow.source_id == source_id)
    if format:
        query = query.filter(func.json_extract(CanonicalEventRow.provenance, '$.parser_id') == format)
    if severity:
        query = query.filter(func.json_extract(CanonicalEventRow.security, '$.severity') == severity)
    if status:
        if status.upper() in ("SUCCESS", "NORMALIZED"):
            query = query.filter(CanonicalEventRow.event_id != None)
        elif status.upper() in ("FAILED", "DLQ"):
            query = query.filter(DLQRecordRow.event_id != None)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (RawEventRow.event_id.ilike(search_term)) |
            (RawEventRow.source_id.ilike(search_term))
        )
    if last_24h:
        from datetime import datetime, timedelta, timezone
        twenty_four_hours_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        query = query.filter(RawEventRow.received_at >= twenty_four_hours_ago)

    # Pagination
    total_events = query.count()
    total_pages = max(1, (total_events + page_size - 1) // page_size)
    
    events_batch = query.order_by(RawEventRow.received_at.desc()).offset(offset).limit(page_size).all()
    
    result = []
    # TODO: Optimise trust score calculation for batches. Currently it performs multiple DB queries and disk I/O per event.
    for raw, canon, dlq in events_batch:
        try:
            from trust.score import compute_trust_score
            ts = compute_trust_score(raw.event_id, db)["trust_score"]
        except Exception:
            ts = None
            
        evt_status = "SUCCESS" if canon else ("FAILED" if dlq else "PENDING")
        
        network = canon.network if canon and canon.network else {}
        security = canon.security if canon and canon.security else {}
        provenance = canon.provenance if canon and canon.provenance else {}
        
        result.append({
            "event_id": raw.event_id,
            "timestamp": canon.timestamp if canon else raw.received_at.isoformat(),
            "source_ip": network.get("source_ip"),
            "destination_ip": network.get("destination_ip"),
            "action": security.get("action"),
            "severity": security.get("severity"),
            "parser_id": provenance.get("parser_id"),
            "source": canon.source if canon else None,
            "network": network,
            "security": security,
            "provenance": provenance,
            "enrichment": canon.enrichment if canon else None,
            "status": evt_status,
            "trust_score": ts
        })

    return {
        "events": result,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_events": total_events,
            "total_pages": total_pages
        }
    }

@router.get("/api/v1/events/filters")
def get_events_filters(db: Session = Depends(get_db)):
    from sqlalchemy import func
    from common.models import RawEventRow, CanonicalEventRow

    # Distinct source_ids
    sources_res = db.query(RawEventRow.source_id).distinct().all()
    sources = [s[0] for s in sources_res if s[0]]

    # Distinct formats (parser_ids)
    formats_res = db.query(func.json_extract(CanonicalEventRow.provenance, '$.parser_id')).distinct().all()
    formats = [f[0] for f in formats_res if f[0]]

    # Distinct severities
    severities_res = db.query(func.json_extract(CanonicalEventRow.security, '$.severity')).distinct().all()
    severities = [s[0] for s in severities_res if s[0]]
    
    statuses = ["SUCCESS", "FAILED", "PENDING"]

    return {
        "sources": sources,
        "formats": formats,
        "severities": severities,
        "statuses": statuses
    }

@router.get("/api/v1/stats")
def get_stats(db: Session = Depends(get_db)):
    # Count normalizations and raw
    total_events = db.query(func.count(CanonicalEventRow.event_id)).scalar() or 0
    total_raw = db.query(func.count(RawEventRow.event_id)).scalar() or 0
    total_batches = db.query(func.count(BatchRow.batch_id)).scalar() or 0
    dlq_count = db.query(func.count(DLQRecordRow.event_id)).scalar() or 0

    last_batch = db.query(BatchRow).order_by(BatchRow.created_at.desc()).first()
    last_batch_merkle_root = last_batch.merkle_root if last_batch else None

    # Count events by parser_id (format proxy)
    all_integrity = db.query(IntegrityRecordRow.parser_id).all()
    format_counts = {}
    for (pid,) in all_integrity:
        fmt = (pid or "unknown").replace("_parser", "")
        format_counts[fmt] = format_counts.get(fmt, 0) + 1

    # Count raw events with no canonical (unknown format + DLQ)
    unknown_count = total_raw - total_events
    if unknown_count > 0:
        format_counts["unknown"] = format_counts.get("unknown", 0) + unknown_count

    return {
        "total_events": total_raw,
        "total_normalized": total_events,
        "dlq_count": dlq_count,
        "events_by_format": format_counts,
        "total_batches": total_batches,
        "last_batch_merkle_root": last_batch_merkle_root
    }

@router.get("/api/v1/events/{event_id}")
def get_canonical_event(event_id: str, db: Session = Depends(get_db)):
    e = db.query(CanonicalEventRow).filter(CanonicalEventRow.event_id == event_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp,
        "source": e.source,
        "network": e.network,
        "security": e.security,
        "provenance": e.provenance,
        "enrichment": e.enrichment
    }

@router.get("/api/v1/events/{event_id}/raw")
def get_raw_event(event_id: str, request: Request, db: Session = Depends(get_db)):
    raw = db.query(RawEventRow).filter(RawEventRow.event_id == event_id).first()
    if not raw:
        raise HTTPException(status_code=404, detail="Raw event not found")
    
    if os.path.exists(raw.storage_uri):
        with open(raw.storage_uri, "rb") as f:
            content = f.read()
        _log_audit(db, request, "viewed_raw_evidence", event_id=event_id)
        return Response(content=content, media_type="application/octet-stream")
    else:
        _log_audit(db, request, "viewed_raw_evidence", event_id=event_id)
        return Response(content=raw.payload, media_type="application/octet-stream")

from integrity.chain import GENESIS_HASH, compute_normalized_hash
from integrity.merkle import compute_merkle_root
from trust.score import compute_trust_score
import hashlib
import json

def _do_verify(event_id: str, db: Session):
    """Core verification logic shared by GET and POST handlers.

    Three possible outcomes:
      - event_id not found in raw_events at all → 404
      - raw event exists but was never normalized (unknown format, no IntegrityRecord)
        → 200 NOT_APPLICABLE with raw hash check only
      - full integrity record exists → full chain + merkle verification
    """
    raw_row = db.query(RawEventRow).filter(RawEventRow.event_id == event_id).first()
    if not raw_row:
        raise HTTPException(status_code=404, detail="Event not found")

    integrity_row = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == event_id).first()

    # --- Case: unknown format — no IntegrityRecord, only check raw evidence ---
    if not integrity_row:
        if raw_row and os.path.exists(raw_row.storage_uri):
            with open(raw_row.storage_uri, "rb") as f:
                r_bytes = f.read()
            recomputed_raw_hash = hashlib.sha256(r_bytes).hexdigest()
            raw_integrity = (recomputed_raw_hash == raw_row.raw_sha256)
        else:
            raw_integrity = False
        return {
            "event_id": event_id,
            "raw_integrity": raw_integrity,
            "normalized_integrity": None,
            "chain_integrity": None,
            "merkle_integrity": None,
            "overall": "NOT_APPLICABLE",
            "reason": "Event was not normalized (unknown format); raw evidence integrity was still checked."
        }

    canonical_row = db.query(CanonicalEventRow).filter(CanonicalEventRow.event_id == event_id).first()

    # 1. Verify Raw
    if raw_row and os.path.exists(raw_row.storage_uri):
        with open(raw_row.storage_uri, "rb") as f:
            r_bytes = f.read()
        recomputed_raw_hash = hashlib.sha256(r_bytes).hexdigest()
    else:
        recomputed_raw_hash = None

    raw_integrity = (recomputed_raw_hash == integrity_row.raw_hash)

    # 2. Verify Normalized
    recomputed_normalized = None
    if canonical_row:
        c_dict = {
            "event_id": canonical_row.event_id,
            "timestamp": canonical_row.timestamp,
            "source": canonical_row.source,
            "network": canonical_row.network,
            "security": canonical_row.security,
            "provenance": canonical_row.provenance,
            "enrichment": canonical_row.enrichment
        }
        recomputed_normalized = compute_normalized_hash(c_dict)

    normalized_integrity = (recomputed_normalized == integrity_row.normalized_hash)

    # 3. Verify Chain
    recomputed_chain_hash = hashlib.sha256(
        (event_id + integrity_row.raw_hash + integrity_row.normalized_hash +
         integrity_row.parser_version + integrity_row.mapping_version +
         integrity_row.previous_chain_hash).encode('utf-8')
    ).hexdigest()

    chain_integrity = (recomputed_chain_hash == integrity_row.chain_hash)

    # 4. Verify Merkle (unbatched events are not tampering — default True)
    merkle_integrity = True
    if integrity_row.batch_id:
        batch = db.query(BatchRow).filter(BatchRow.batch_id == integrity_row.batch_id).first()
        if batch:
            batch_records = db.query(IntegrityRecordRow).filter(
                IntegrityRecordRow.batch_id == integrity_row.batch_id
            ).order_by(IntegrityRecordRow.seq_id.asc()).all()
            hashes = [r.chain_hash for r in batch_records]
            recomputed_merkle = compute_merkle_root(hashes)
            merkle_integrity = (recomputed_merkle == batch.merkle_root)
        else:
            merkle_integrity = False

    overall = "VERIFIED" if all([raw_integrity, normalized_integrity, chain_integrity, merkle_integrity]) else "TAMPERING_DETECTED"

    return {
        "event_id": event_id,
        "raw_integrity": raw_integrity,
        "normalized_integrity": normalized_integrity,
        "chain_integrity": chain_integrity,
        "merkle_integrity": merkle_integrity,
        "overall": overall
    }

@router.get("/api/v1/events/{event_id}/verify")
def verify_event_get(event_id: str, db: Session = Depends(get_db)):
    return _do_verify(event_id, db)

@router.post("/api/v1/events/{event_id}/verify")
def verify_event_post(event_id: str, request: Request, db: Session = Depends(get_db)):
    result = _do_verify(event_id, db)
    _log_audit(db, request, "verified_event", event_id=event_id)
    return result

@router.get("/api/v1/events/{event_id}/trust-score")
def get_trust_score(event_id: str, db: Session = Depends(get_db)):
    try:
        return compute_trust_score(event_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/api/v1/events/{event_id}/trace")
def trace_event(event_id: str, db: Session = Depends(get_db)):
    integrity_row = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == event_id).first()
    if not integrity_row:
        raise HTTPException(status_code=404, detail="Integrity record not found")
        
    res = {
        "raw_hash": integrity_row.raw_hash,
        "normalized_hash": integrity_row.normalized_hash,
        "parser_id": integrity_row.parser_id,
        "parser_version": integrity_row.parser_version,
        "mapping_version": integrity_row.mapping_version,
        "chain_hash": integrity_row.chain_hash,
        "merkle_batch_id": integrity_row.batch_id,
        "merkle_root": None
    }
    
    if integrity_row.batch_id:
        batch = db.query(BatchRow).filter(BatchRow.batch_id == integrity_row.batch_id).first()
        if batch:
            res["merkle_root"] = batch.merkle_root

    # Embed trust score into trace response
    try:
        ts = compute_trust_score(event_id, db)
        res["trust_score"] = ts["trust_score"]
        res["score_breakdown"] = ts["score_breakdown"]
    except Exception:
        res["trust_score"] = None
        res["score_breakdown"] = None

    return res

@router.get("/api/v1/events/{event_id}/custody-certificate")
def get_custody_certificate(event_id: str, request: Request, format: str = "json", db: Session = Depends(get_db)):
    if format == "pdf":
        raise HTTPException(status_code=501, detail="PDF format is not supported in this MVP (reportlab not installed, skipping to save unneeded complexity). JSON only.")
        
    import uuid
    
    raw_row = db.query(RawEventRow).filter(RawEventRow.event_id == event_id).first()
    if not raw_row:
        raise HTTPException(status_code=404, detail="Event not found")
        
    # Reuse existing verification logic
    verify_result = _do_verify(event_id, db)
    
    # Try fetching trace safely
    trace_data = None
    integrity_row = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == event_id).first()
    if integrity_row:
        # We can just call trace_event, but it raises HTTP exceptions if not found which we handled above
        trace_data = trace_event(event_id, db)
        
    # Get trust score safely
    ts_data = None
    try:
        ts_data = compute_trust_score(event_id, db)
    except Exception:
        pass

    overall = verify_result["overall"]
    if overall == "VERIFIED" and integrity_row and not integrity_row.batch_id:
        overall = "VERIFIED_PENDING_BATCH"

    cert = {
        "certificate_id": str(uuid.uuid4()),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by_system": "ULPF v1.0-MVP",
        "event_id": event_id,
        "source_id": raw_row.source_id,
        "ingestion_timestamp": raw_row.received_at.isoformat() + "Z" if raw_row.received_at else None,
        "evidence": {
            "raw_sha256": raw_row.raw_sha256,
            "normalized_sha256": trace_data.get("normalized_hash") if trace_data else None,
            "raw_storage_reference": raw_row.storage_uri
        },
        "processing_lineage": {
            "parser_id": trace_data.get("parser_id") if trace_data else None,
            "parser_version": trace_data.get("parser_version") if trace_data else None,
            "mapping_version": trace_data.get("mapping_version") if trace_data else None
        },
        "chain_of_custody": {
            "chain_hash": trace_data.get("chain_hash") if trace_data else None,
            "previous_chain_hash": integrity_row.previous_chain_hash if integrity_row else None,
            "merkle_batch_id": trace_data.get("merkle_batch_id") if trace_data else None,
            "merkle_root": trace_data.get("merkle_root") if trace_data else None,
            "anchor_reference": None
        },
        "verification_result": {
            "overall": overall,
            "raw_integrity": verify_result["raw_integrity"],
            "normalized_integrity": verify_result["normalized_integrity"],
            "chain_integrity": verify_result["chain_integrity"],
            "merkle_integrity": verify_result["merkle_integrity"] if verify_result["overall"] != "NOT_APPLICABLE" else None
        },
        "trust_score": {
            "score": ts_data["trust_score"] if ts_data else None,
            "checks_summary": ts_data["checks"] if ts_data else []
        }
    }
    
    if integrity_row and integrity_row.batch_id:
        batch = db.query(BatchRow).filter(BatchRow.batch_id == integrity_row.batch_id).first()
        if batch:
            cert["chain_of_custody"]["anchor_reference"] = batch.fake_tx_id
            
    # Certificate Hash computation (to make the document tamper-evident)
    # Computed over canonical JSON of the entire cert, with the certificate_hash field excluded.
    cert_json = json.dumps(cert, separators=(',', ':'), sort_keys=True)
    cert["certificate_hash"] = hashlib.sha256(cert_json.encode("utf-8")).hexdigest()
    
    _log_audit(db, request, "generated_certificate", event_id=event_id)
    return cert

@router.get("/api/v1/dlq")
def list_dlq(db: Session = Depends(get_db)):
    records = db.query(DLQRecordRow).order_by(DLQRecordRow.timestamp.desc()).all()
    return [
        {
            "event_id": r.event_id,
            "raw_sha256": r.raw_sha256,
            "failure_stage": r.failure_stage,
            "error_code": r.error_code,
            "error_message": r.error_message,
            "attempt": r.attempt,
            "timestamp": r.timestamp
        } for r in records
    ]

@router.get("/api/v1/dlq/{event_id}")
def get_dlq_record(event_id: str, db: Session = Depends(get_db)):
    r = db.query(DLQRecordRow).filter(DLQRecordRow.event_id == event_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="DLQ record not found")
    return {
        "event_id": r.event_id,
        "raw_sha256": r.raw_sha256,
        "failure_stage": r.failure_stage,
        "error_code": r.error_code,
        "error_message": r.error_message,
        "attempt": r.attempt,
        "timestamp": r.timestamp
    }

# ── Audit Log ───────────────────────────────────────────────────────
@router.get("/api/v1/audit")
def list_audit_logs(
    page: int = 1,
    page_size: int = 25,
    username: str = None,
    action: str = None,
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db),
):
    if page_size > 100:
        page_size = 100

    query = db.query(AuditLogEntry)

    if username:
        query = query.filter(AuditLogEntry.username == username)
    if action:
        query = query.filter(AuditLogEntry.action == action)
    if start_date:
        try:
            sd = datetime.fromisoformat(start_date)
            query = query.filter(AuditLogEntry.timestamp >= sd)
        except ValueError:
            pass
    if end_date:
        try:
            ed = datetime.fromisoformat(end_date)
            query = query.filter(AuditLogEntry.timestamp <= ed)
        except ValueError:
            pass

    total_events = query.count()
    total_pages = max(1, (total_events + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    entries = query.order_by(AuditLogEntry.timestamp.desc()).offset(offset).limit(page_size).all()

    return {
        "entries": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "username": e.username,
                "action": e.action,
                "event_id": e.event_id,
                "source_id": e.source_id,
                "ip_address": e.ip_address,
            }
            for e in entries
        ],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_events": total_events,
            "total_pages": total_pages,
        },
    }

# Onboarding Endpoints
@router.get("/api/v1/onboarding/pending")
def list_pending_sources(db: Session = Depends(get_db)):
    sources = db.query(PendingSourceRow).filter(PendingSourceRow.status == "pending").all()
    return [
        {
            "source_id": s.source_id,
            "first_seen_at": s.first_seen_at,
            "suggested_mapping": s.suggested_mapping
        }
        for s in sources
    ]

@router.get("/api/v1/onboarding/pending/{source_id}")
def get_pending_source(source_id: str, db: Session = Depends(get_db)):
    s = db.query(PendingSourceRow).filter(PendingSourceRow.source_id == source_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Source not found")
    return {
        "source_id": s.source_id,
        "first_seen_at": s.first_seen_at,
        "sample_payload": s.sample_payload,
        "discovered_fields": s.discovered_fields,
        "suggested_mapping": s.suggested_mapping,
        "status": s.status,
        "approved_mapping": s.approved_mapping
    }

class ApproveSourceRequest(BaseModel):
    overrides: dict = {}

@router.post("/api/v1/onboarding/pending/{source_id}/approve")
def approve_pending_source(source_id: str, req: ApproveSourceRequest, request: Request, db: Session = Depends(get_db)):
    s = db.query(PendingSourceRow).filter(PendingSourceRow.source_id == source_id).first()
    if not s or s.status != "pending":
        raise HTTPException(status_code=404, detail="Pending source not found or not pending")
    
    final_mapping = s.suggested_mapping or {}
    
    # Apply overrides
    for key, c_field in req.overrides.items():
        if key in final_mapping:
            final_mapping[key]["canonical_field"] = c_field
            final_mapping[key]["confidence"] = 1.0
        else:
            final_mapping[key] = {"canonical_field": c_field, "confidence": 1.0}
            
    s.approved_mapping = final_mapping
    s.status = "approved"
    db.commit()
    _log_audit(db, request, "approved_mapping", source_id=source_id)
    return {"status": "approved", "source_id": source_id, "approved_mapping": final_mapping}

@router.post("/api/v1/onboarding/pending/{source_id}/reject")
def reject_pending_source(source_id: str, request: Request, db: Session = Depends(get_db)):
    s = db.query(PendingSourceRow).filter(PendingSourceRow.source_id == source_id).first()
    if not s or s.status != "pending":
        raise HTTPException(status_code=404, detail="Pending source not found or not pending")
    
    s.status = "rejected"
    db.commit()
    _log_audit(db, request, "rejected_mapping", source_id=source_id)
    return {"status": "rejected", "source_id": source_id}

# ── Playground ──────────────────────────────────────────────────────
from detection.detector import detect
from parser.json_parser import parse_json
from parser.syslog_parser import parse_syslog
from parser.cef_parser import parse_cef
from parser.leef_parser import parse_leef
from parser.drain3_parser import parse_drain3
from normalization.json_mapper import map_to_canonical
from enrichment import ENRICHMENT_CONFIG
from enrichment.ip_classifier import classify_ip
from enrichment.geoip import get_country_code
from normalization.schema import EventEnrichment
from integrity.chain import compute_normalized_hash

@router.post("/api/v1/playground/process")
def playground_process(
    payload_body: Any = Body(
        default=None, 
        description="Payload can be any JSON object, list, or a raw string log (ensure raw strings are quoted)."
    )
):
    if not payload_body:
        return {"error": "Empty payload"}

    if isinstance(payload_body, dict) and "payload" in payload_body and len(payload_body) <= 2:
        p = payload_body["payload"]
        payload_str = json.dumps(p) if isinstance(p, (dict, list)) else str(p)
    else:
        payload_str = json.dumps(payload_body) if isinstance(payload_body, (dict, list)) else str(payload_body)

    payload_bytes = payload_str.encode("utf-8")
    raw_sha256 = hashlib.sha256(payload_bytes).hexdigest()

    result = {
        "raw_input": payload_str,
        "detection": None,
        "parsing": None,
        "normalization": None,
        "enrichment": None,
        "validation": None,
        "integrity": None,
    }

    # 1. Detection
    try:
        det = detect(payload_bytes)
        result["detection"] = det.model_dump()
    except Exception as e:
        result["detection"] = {"error": str(e)}
        return result

    # 2. Parsing
    parsed_data = None
    try:
        if det.parser_id == "json_parser":
            parsed_data = parse_json(payload_bytes)
        elif det.parser_id == "syslog_parser":
            parsed_data = parse_syslog(payload_bytes)
        elif det.parser_id == "cef_parser":
            parsed_data = parse_cef(payload_bytes)
        elif det.parser_id == "leef_parser":
            parsed_data = parse_leef(payload_bytes)
        elif det.parser_id == "drain3_parser":
            parsed_data = parse_drain3(payload_bytes)

        if parsed_data is not None:
            result["parsing"] = parsed_data
        else:
            result["parsing"] = {"note": "No parser matched or parser returned None"}
    except Exception as e:
        result["parsing"] = {"error": str(e)}
        return result

    if parsed_data is None:
        return result

    # 3. Normalization
    try:
        event_id = "playground-preview"
        canonical = map_to_canonical(event_id, parsed_data, parser_id=det.parser_id or "unknown")
        result["normalization"] = {
            "event_id": canonical.event_id,
            "timestamp": canonical.timestamp,
            "source": canonical.source.model_dump(),
            "network": canonical.network.model_dump(),
            "security": canonical.security.model_dump(),
            "provenance": canonical.provenance.model_dump(),
        }
    except Exception as e:
        result["normalization"] = {"error": str(e)}
        return result

    # 4. Enrichment
    try:
        enrichment_data = EventEnrichment()
        src_ip = canonical.network.source_ip
        dst_ip = canonical.network.destination_ip
        if ENRICHMENT_CONFIG.get("ip_classification"):
            if src_ip:
                enrichment_data.source_ip_class = classify_ip(src_ip)
            if dst_ip:
                enrichment_data.destination_ip_class = classify_ip(dst_ip)
        if ENRICHMENT_CONFIG.get("geoip"):
            if dst_ip and enrichment_data.destination_ip_class == "public":
                enrichment_data.destination_geo_country = get_country_code(dst_ip)
        result["enrichment"] = enrichment_data.model_dump()
    except Exception as e:
        result["enrichment"] = {"error": str(e)}

    # 5. Validation (simple field completeness check)
    try:
        net = canonical.network
        sec = canonical.security
        filled = sum(1 for v in [net.source_ip, net.destination_ip, net.source_port, net.destination_port, sec.action, sec.severity] if v is not None)
        result["validation"] = {
            "fields_populated": filled,
            "fields_total": 6,
            "completeness_pct": round(filled / 6 * 100, 1),
            "has_source_ip": net.source_ip is not None,
            "has_destination_ip": net.destination_ip is not None,
            "has_action": sec.action is not None,
        }
    except Exception as e:
        result["validation"] = {"error": str(e)}

    # 6. Integrity (hash preview)
    try:
        c_dict = result["normalization"].copy()
        c_dict["enrichment"] = result.get("enrichment")
        norm_hash = compute_normalized_hash(c_dict)
        result["integrity"] = {
            "raw_sha256": raw_sha256,
            "normalized_sha256": norm_hash,
            "note": "These are the hashes that would be stored in the integrity chain."
        }
    except Exception as e:
        result["integrity"] = {"error": str(e)}

    return result


# --- NEW BATCHES ENDPOINTS ---

@router.get("/api/v1/batches")
def list_batches(page: int = 1, page_size: int = 25, db: Session = Depends(get_db)):
    offset = (page - 1) * page_size
    batches = db.query(BatchRow).order_by(BatchRow.created_at.desc()).offset(offset).limit(page_size).all()
    total = db.query(func.count(BatchRow.batch_id)).scalar() or 0
    
    data = []
    for b in batches:
        chain_continuous = False
        first_evt = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == b.first_event_id).first()
        if first_evt:
            if first_evt.seq_id == 1:
                chain_continuous = True
            else:
                prev_evt = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.seq_id == first_evt.seq_id - 1).first()
                if prev_evt and prev_evt.chain_hash == first_evt.previous_chain_hash:
                    chain_continuous = True

        data.append({
            "batch_id": b.batch_id,
            "created_at": b.created_at,
            "event_count": b.event_count,
            "first_event_id": b.first_event_id,
            "last_event_id": b.last_event_id,
            "merkle_root": b.merkle_root,
            "anchor_reference": b.fake_tx_id,
            "chain_continuous": chain_continuous
        })
        
    return {
        "data": data,
        "page": page,
        "page_size": page_size,
        "total": total
    }

@router.get("/api/v1/batches/stats")
def get_batch_stats(db: Session = Depends(get_db)):
    total_batches = db.query(func.count(BatchRow.batch_id)).scalar() or 0
    if total_batches == 0:
        return {
            "total_batches": 0,
            "average_batch_size": 0,
            "first_batch_created_at": None,
            "latest_batch_created_at": None,
            "overall_chain_continuous": True
        }
        
    total_events = db.query(func.sum(BatchRow.event_count)).scalar() or 0
    avg_batch_size = total_events / total_batches if total_batches > 0 else 0
    
    first_b = db.query(BatchRow).order_by(BatchRow.created_at.asc()).first()
    latest_b = db.query(BatchRow).order_by(BatchRow.created_at.desc()).first()
    
    records = db.query(IntegrityRecordRow).order_by(IntegrityRecordRow.seq_id.asc()).all()
    overall_continuous = True
    for i in range(1, len(records)):
        if records[i].previous_chain_hash != records[i-1].chain_hash:
            overall_continuous = False
            break

    return {
        "total_batches": total_batches,
        "average_batch_size": round(avg_batch_size, 2),
        "first_batch_created_at": first_b.created_at,
        "latest_batch_created_at": latest_b.created_at,
        "overall_chain_continuous": overall_continuous
    }

@router.get("/api/v1/batches/{batch_id}")
def get_batch_detail(batch_id: str, db: Session = Depends(get_db)):
    b = db.query(BatchRow).filter(BatchRow.batch_id == batch_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Batch not found")
        
    chain_continuous = False
    first_evt = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.event_id == b.first_event_id).first()
    if first_evt:
        if first_evt.seq_id == 1:
            chain_continuous = True
        else:
            prev_evt = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.seq_id == first_evt.seq_id - 1).first()
            if prev_evt and prev_evt.chain_hash == first_evt.previous_chain_hash:
                chain_continuous = True
                
    evts = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.batch_id == batch_id).order_by(IntegrityRecordRow.seq_id.asc()).all()
    event_ids = [e.event_id for e in evts]
    
    anchor_log_entry = None
    try:
        if os.path.exists("data/integrity/anchor_log.jsonl"):
            with open("data/integrity/anchor_log.jsonl", "r") as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get("batch_id") == batch_id:
                        anchor_log_entry = entry
                        break
    except Exception:
        pass

    return {
        "batch_id": b.batch_id,
        "created_at": b.created_at,
        "event_count": b.event_count,
        "first_event_id": b.first_event_id,
        "last_event_id": b.last_event_id,
        "merkle_root": b.merkle_root,
        "anchor_reference": b.fake_tx_id,
        "chain_continuous": chain_continuous,
        "event_ids": event_ids,
        "anchor_log": anchor_log_entry
    }

@router.post("/api/v1/batches/{batch_id}/reverify")
def reverify_batch(batch_id: str, db: Session = Depends(get_db)):
    b = db.query(BatchRow).filter(BatchRow.batch_id == batch_id).first()
    if not b:
        raise HTTPException(status_code=404, detail="Batch not found")
        
    evts = db.query(IntegrityRecordRow).filter(IntegrityRecordRow.batch_id == batch_id).order_by(IntegrityRecordRow.seq_id.asc()).all()
    if not evts:
        raise HTTPException(status_code=400, detail="No events found for this batch")
        
    hashes = [e.chain_hash for e in evts]
    recomputed_root = compute_merkle_root(hashes)
    
    match = (recomputed_root == b.merkle_root)
    
    return {
        "batch_id": batch_id,
        "recomputed_root": recomputed_root,
        "stored_root": b.merkle_root,
        "match": match,
        "verified_at": datetime.utcnow()
    }
