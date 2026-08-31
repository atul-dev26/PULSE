from difflib import SequenceMatcher
import re

CANONICAL_FIELDS = {
    "source.vendor": ["vendor", "company"],
    "source.product": ["product", "app", "application"],
    "source.device_id": ["device_id", "host", "hostname"],
    "network.protocol": ["protocol", "proto"],
    "network.source_ip": ["src", "src_ip", "source_ip", "sourceAddress", "srcAddr"],
    "network.source_port": ["src_port", "source_port", "sourcePort", "sport", "spt"],
    "network.destination_ip": ["dst", "dest", "dst_ip", "destination_ip", "destinationAddress", "destAddr", "dstAddr"],
    "network.destination_port": ["dest_port", "destination_port", "destinationPort", "dport", "dpt", "dstPort"],
    "security.action": ["action", "act", "decision"],
    "security.severity": ["severity", "level", "sev"],
    "timestamp": ["timestamp", "time", "date"]
}

def infer_mappings(discovered_fields: dict) -> dict:
    suggestions = {}
    for key, value in discovered_fields.items():
        best_field = None
        best_score = 0.0
        
        lower_key = key.lower()
        
        for c_field, aliases in CANONICAL_FIELDS.items():
            for alias in aliases:
                score = SequenceMatcher(None, lower_key, alias.lower()).ratio()
                
                # Heuristics based on value shape
                if c_field.endswith("_ip"):
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(value)):
                        score += 0.3
                elif c_field.endswith("_port"):
                    if str(value).isdigit() and int(value) <= 65535:
                        score += 0.3
                elif c_field == "security.action":
                    if str(value).lower() in {"allow", "deny", "block", "drop", "accept", "reject", "success", "failed", "login"}:
                        score += 0.4
                        
                if score > best_score:
                    best_score = score
                    best_field = c_field
                    
        best_score = min(best_score, 1.0)
        
        if best_score >= 0.6 and best_field:
            suggestions[key] = {
                "canonical_field": best_field,
                "confidence": round(best_score, 2)
            }
            
    return suggestions
