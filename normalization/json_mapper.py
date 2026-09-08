from typing import Any, List, Dict
from datetime import datetime

from .schema import (
    CanonicalEvent,
    EventSource,
    EventNetwork,
    EventSecurity,
    EventProvenance,
)

import re

def resolve_field(event: Dict[str, Any], aliases: List[str]) -> Any:
    for alias in aliases:
        if alias in event:
            return event[alias]
            
    # Drain3 Fallback Strategy: blindly scan the extracted string parameters.
    if event.get("_is_drain3"):
        # We know aliases[0] is often the primary key, let's use it as a hint.
        hint = aliases[0].lower()
        for v in event.values():
            if isinstance(v, str):
                # If we are resolving a port...
                if "port" in hint or "spt" in hint or "dpt" in hint:
                    if v.isdigit():
                        return v
                # If we are resolving an IP address...
                elif "ip" in hint or "address" in hint or "src" in hint or "dst" in hint:
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
                        return v
                # If we are resolving an action...
                if "act" in hint:
                    if v.lower() in {"allow", "deny", "drop", "failed", "login", "success", "accept", "reject", "block"}:
                        return v
    return None

def map_to_canonical(event_id: str, parsed_event: dict, parser_id: str = "json_parser") -> CanonicalEvent:
    vendor = resolve_field(parsed_event, ["vendor", "company"])
    product = resolve_field(parsed_event, ["product", "app", "application"])
    device_id = resolve_field(parsed_event, ["device_id", "host", "hostname"])
    
    protocol = resolve_field(parsed_event, ["protocol", "proto"])
    source_ip = resolve_field(parsed_event, ["src", "src_ip", "source_ip", "sourceAddress"])
    source_port = resolve_field(parsed_event, ["src_port", "source_port", "sourcePort", "sport", "spt"])
    destination_ip = resolve_field(parsed_event, ["dst", "dest", "dst_ip", "destination_ip", "destinationAddress"])
    destination_port = resolve_field(parsed_event, ["dest_port", "destination_port", "destinationPort", "dport", "dpt"])
    
    action = resolve_field(parsed_event, ["action", "act", "event_type"])
    severity = resolve_field(parsed_event, ["severity", "level", "sev"])
    
    timestamp = resolve_field(parsed_event, ["timestamp", "time", "date"])
    if not timestamp:
        timestamp = datetime.utcnow().isoformat()
        
    source = EventSource(vendor=vendor, product=product, device_id=device_id)
    network = EventNetwork(
        protocol=protocol,
        source_ip=source_ip,
        source_port=int(source_port) if source_port is not None else None,
        destination_ip=destination_ip,
        destination_port=int(destination_port) if destination_port is not None else None,
    )
    security = EventSecurity(action=action, severity=severity)
    raw_tmp = parsed_event.get("raw_template")
    tmp_params = parsed_event.get("template_params")
    
    provenance = EventProvenance(
        parser_id=parser_id,
        parser_version="1.0.0",
        mapping_version="1.0.0",
        raw_template=raw_tmp,
        template_params=tmp_params
    )
    
    return CanonicalEvent(
        event_id=event_id,
        timestamp=str(timestamp),
        source=source,
        network=network,
        security=security,
        provenance=provenance
    )
