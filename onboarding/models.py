from sqlalchemy import Column, String, DateTime, JSON
from datetime import datetime
from common.database import Base

class PendingSourceRow(Base):
    __tablename__ = "pending_sources"
    
    source_id = Column(String, primary_key=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    sample_payload = Column(String)
    discovered_fields = Column(JSON)
    suggested_mapping = Column(JSON)
    status = Column(String, default="pending") # "pending", "approved", "rejected"
    approved_mapping = Column(JSON, nullable=True)
