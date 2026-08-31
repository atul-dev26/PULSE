from pydantic import BaseModel
from typing import Optional

class EventSource(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    device_id: Optional[str] = None

class EventNetwork(BaseModel):
    protocol: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

class EventSecurity(BaseModel):
    action: Optional[str] = None
    severity: Optional[str] = None

class EventProvenance(BaseModel):
    parser_id: str
    parser_version: str
    mapping_version: str
    raw_template: Optional[str] = None
    template_params: Optional[list] = None

class EventEnrichment(BaseModel):
    source_ip_class: Optional[str] = None
    destination_ip_class: Optional[str] = None
    destination_geo_country: Optional[str] = None

class CanonicalEvent(BaseModel):
    event_id: str
    timestamp: str
    source: EventSource
    network: EventNetwork
    security: EventSecurity
    provenance: EventProvenance
    enrichment: Optional[EventEnrichment] = None
