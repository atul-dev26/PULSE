from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from common.database import get_db
from common.models import RawEventRow, CanonicalEventRow, DLQRecordRow
from auth.dependencies import get_current_user
from trust.score import compute_trust_score
import datetime
import csv
import io
import json

router = APIRouter(dependencies=[Depends(get_current_user)])

def build_export_query(db, start, end, source_id, severity, status, format_filter):
    query = db.query(RawEventRow, CanonicalEventRow, DLQRecordRow)\
        .outerjoin(CanonicalEventRow, RawEventRow.event_id == CanonicalEventRow.event_id)\
        .outerjoin(DLQRecordRow, RawEventRow.event_id == DLQRecordRow.event_id)
        
    if start:
        try:
            start_dt = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))
            query = query.filter(RawEventRow.received_at >= start_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start timestamp format")
    if end:
        try:
            end_dt = datetime.datetime.fromisoformat(end.replace("Z", "+00:00"))
            query = query.filter(RawEventRow.received_at <= end_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end timestamp format")
    if source_id:
        query = query.filter(RawEventRow.source_id == source_id)
    if format_filter:
        query = query.filter(func.json_extract(CanonicalEventRow.provenance, '$.parser_id') == format_filter)
    if severity:
        query = query.filter(func.json_extract(CanonicalEventRow.security, '$.severity') == severity)
    if status:
        if status.upper() == "SUCCESS":
            query = query.filter(CanonicalEventRow.event_id.isnot(None))
        elif status.upper() == "FAILED":
            query = query.filter(DLQRecordRow.event_id.isnot(None))
            
    return query

@router.get("/api/v1/export/preview")
def preview_export(
    start: str = None,
    end: str = None,
    source_id: str = None,
    severity: str = None,
    status: str = None,
    format_filter: str = None,
    db: Session = Depends(get_db)
):
    query = build_export_query(db, start, end, source_id, severity, status, format_filter)
    count = query.count()
    return {"total_matching": count}

@router.get("/api/v1/export")
def export_events(
    format: str = Query("csv", description="csv, json, or cef"),
    start: str = None,
    end: str = None,
    source_id: str = None,
    severity: str = None,
    status: str = None,
    format_filter: str = None,
    db: Session = Depends(get_db)
):
    if format not in ("csv", "json", "cef"):
        raise HTTPException(status_code=400, detail="Unsupported format")
        
    query = build_export_query(db, start, end, source_id, severity, status, format_filter)
    results = query.all()
    
    events = []
    for raw, can, dlq in results:
        evt_status = "FAILED" if dlq else "SUCCESS" if can else "PENDING"
        ts = can.timestamp if can and can.timestamp else raw.received_at.isoformat()
        
        try:
            trust = compute_trust_score(raw.event_id, db)["trust_score"]
        except Exception:
            trust = None

        sev = "UNKNOWN"
        action = "UNKNOWN"
        fmt = "UNKNOWN"
        parser_id = "UNKNOWN"
        src_ip = ""
        dst_ip = ""
        src_port = ""
        dst_port = ""
        proto = ""
        
        if can:
            sec = can.security or {}
            sev = sec.get("severity", "UNKNOWN")
            action = sec.get("action", "UNKNOWN")
            prov = can.provenance or {}
            parser_id = prov.get("parser_id", "UNKNOWN")
            fmt = parser_id.replace("_parser", "")
            net = can.network or {}
            src_ip = net.get("source_ip", "")
            dst_ip = net.get("destination_ip", "")
            src_port = net.get("source_port", "")
            dst_port = net.get("destination_port", "")
            proto = net.get("protocol", "")
            
        events.append({
            "event_id": raw.event_id,
            "timestamp": ts,
            "source": raw.source_id,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "action": action,
            "severity": sev,
            "status": evt_status,
            "trust_score": trust,
            "format": fmt,
            "parser_id": parser_id
        })

    if format == "json":
        return JSONResponse(content=events)
        
    if format == "cef":
        def generate_cef():
            sev_map = {"low": 3, "medium": 5, "high": 8, "critical": 10, "UNKNOWN": 0}
            for e in events:
                sev_num = sev_map.get(str(e["severity"]).lower(), 0)
                cef_header = f'CEF:0|ULPF|Event|1.0|{e["parser_id"]}|{e["action"]}|{sev_num}|'
                ext = []
                if e["timestamp"]: ext.append(f'rt={e["timestamp"]}')
                if e["source_ip"]: ext.append(f'src={e["source_ip"]}')
                if e["destination_ip"]: ext.append(f'dst={e["destination_ip"]}')
                if e["source_port"]: ext.append(f'spt={e["source_port"]}')
                if e["destination_port"]: ext.append(f'dpt={e["destination_port"]}')
                if e["protocol"]: ext.append(f'proto={e["protocol"]}')
                if e["status"]: ext.append(f'cs1={e["status"]} cs1Label=Status')
                if e["trust_score"] is not None: ext.append(f'cn1={e["trust_score"]} cn1Label=TrustScore')
                
                yield cef_header + " ".join(ext) + "\n"
                
        return StreamingResponse(generate_cef(), media_type="text/plain", headers={"Content-Disposition": "attachment; filename=export.cef"})
        
    # CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["event_id", "timestamp", "source", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "action", "severity", "status", "trust_score", "format", "parser_id"])
    writer.writeheader()
    for e in events:
        writer.writerow(e)
        
    response = Response(content=output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=export.csv"
    response.headers["Content-Type"] = "text/csv"
    return response
