from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from common.database import get_db
from common.models import RawEventRow, CanonicalEventRow, DLQRecordRow
import datetime
import io

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
except ImportError:
    pass

router = APIRouter()

def build_report_query(db, start, end, source_id, severity, format):
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
    if format:
        query = query.filter(func.json_extract(CanonicalEventRow.provenance, '$.parser_id') == format)
    if severity:
        query = query.filter(func.json_extract(CanonicalEventRow.security, '$.severity') == severity)
        
    return query

@router.get("/api/v1/reports/preview")
def preview_report(
    start: str = None,
    end: str = None,
    source_id: str = None,
    severity: str = None,
    format: str = None,
    db: Session = Depends(get_db)
):
    query = build_report_query(db, start, end, source_id, severity, format)
    
    total_events = query.count()
    events = query.all()
    
    severity_breakdown = {}
    format_breakdown = {}
    status_breakdown = {"SUCCESS": 0, "FAILED": 0, "PENDING": 0}
    
    for raw, canon, dlq in events:
        if canon:
            status_breakdown["SUCCESS"] += 1
            sec = canon.security if canon.security else {}
            sev = sec.get("severity", "unknown")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            
            prov = canon.provenance if canon.provenance else {}
            fmt = prov.get("parser_id", "unknown")
            format_breakdown[fmt] = format_breakdown.get(fmt, 0) + 1
        elif dlq:
            status_breakdown["FAILED"] += 1
        else:
            status_breakdown["PENDING"] += 1
            
    return {
        "total_events": total_events,
        "severity_breakdown": severity_breakdown,
        "format_breakdown": format_breakdown,
        "status_breakdown": status_breakdown
    }

@router.get("/api/v1/reports/pdf")
def generate_pdf_report(
    start: str = None,
    end: str = None,
    source_id: str = None,
    severity: str = None,
    format: str = None,
    db: Session = Depends(get_db)
):
    query = build_report_query(db, start, end, source_id, severity, format)
    events = query.order_by(RawEventRow.received_at.desc()).all()
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    normal_style = styles['Normal']
    
    elements.append(Paragraph("PULSE Evidence Report", title_style))
    elements.append(Spacer(1, 12))
    
    gen_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(f"Generated At: {gen_time}", normal_style))
    filters_text = f"Filters: start={start or 'Any'}, end={end or 'Any'}, source={source_id or 'Any'}, severity={severity or 'Any'}, format={format or 'Any'}"
    elements.append(Paragraph(filters_text, normal_style))
    elements.append(Spacer(1, 24))
    
    # Summary
    elements.append(Paragraph("Summary", styles['Heading2']))
    total = len(events)
    success = sum(1 for _, c, _ in events if c is not None)
    failed = sum(1 for _, c, d in events if c is None and d is not None)
    elements.append(Paragraph(f"Total Events: {total} | Success: {success} | Failed: {failed}", normal_style))
    elements.append(Spacer(1, 24))
    
    # Table data
    data = [["Event ID", "Timestamp", "Source", "Severity", "Status", "Trust Score"]]
    
    for raw, canon, dlq in events:
        eid = raw.event_id[:8] + "..." if len(raw.event_id) > 8 else raw.event_id
        ts = raw.received_at.strftime("%Y-%m-%d %H:%M:%S")
        src = raw.source_id
        
        status = "PENDING"
        sev = "N/A"
        if canon:
            status = "SUCCESS"
            sec = canon.security if canon.security else {}
            sev = sec.get("severity", "N/A")
        elif dlq:
            status = "FAILED"
            
        try:
            from trust.score import compute_trust_score
            ts_val = str(compute_trust_score(raw.event_id, db)["trust_score"])
        except Exception:
            ts_val = "N/A"
            
        data.append([eid, ts, src, sev, status, ts_val])
        
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    
    elements.append(table)
    doc.build(elements)
    
    pdf = buffer.getvalue()
    buffer.close()
    
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": "attachment; filename=pulse_report.pdf"
    })
