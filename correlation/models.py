import uuid
from sqlalchemy import Column, String, DateTime, JSON
from datetime import datetime
from common.database import Base


class IncidentRow(Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    technique = Column(String, nullable=False)          # MITRE ATT&CK ID, e.g. T1110
    severity = Column(String, nullable=False)            # high, critical, medium
    source_ip = Column(String, nullable=False, index=True)
    event_ids = Column(JSON, nullable=False, default=list)  # list of contributing event_id strings
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    status = Column(String, nullable=False, default="open")  # open / acknowledged
    created_at = Column(DateTime, default=datetime.utcnow)
