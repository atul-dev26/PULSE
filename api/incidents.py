"""
API endpoints for incidents produced by the correlation engine.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from common.database import get_db
from correlation.models import IncidentRow
from common.models import CanonicalEventRow
from auth.dependencies import get_current_user

router = APIRouter(prefix="/api/v1", dependencies=[Depends(get_current_user)])


@router.get("/incidents")
def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status: open / acknowledged"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List detected incidents, paginated, with event_ids included."""
    query = db.query(IncidentRow)

    if status:
        query = query.filter(IncidentRow.status == status)

    total = query.count()
    incidents = (
        query
        .order_by(IncidentRow.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "technique": inc.technique,
                "severity": inc.severity,
                "source_ip": inc.source_ip,
                "event_ids": inc.event_ids,
                "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
                "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
                "status": inc.status,
                "created_at": inc.created_at.isoformat() if inc.created_at else None,
            }
            for inc in incidents
        ],
    }


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Full incident detail including ordered chain of contributing events."""
    incident = db.query(IncidentRow).filter(IncidentRow.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch the contributing canonical events in order
    contributing_events = []
    for eid in (incident.event_ids or []):
        ev = db.query(CanonicalEventRow).filter(CanonicalEventRow.event_id == eid).first()
        if ev:
            contributing_events.append({
                "event_id": ev.event_id,
                "timestamp": ev.timestamp,
                "source": ev.source,
                "network": ev.network,
                "security": ev.security,
                "enrichment": ev.enrichment,
            })

    # Sort events by timestamp
    contributing_events.sort(key=lambda e: e.get("timestamp") or "")

    return {
        "incident_id": incident.incident_id,
        "technique": incident.technique,
        "severity": incident.severity,
        "source_ip": incident.source_ip,
        "event_ids": incident.event_ids,
        "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
        "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
        "status": incident.status,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "contributing_events": contributing_events,
    }
