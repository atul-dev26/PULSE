import re

def discover_fields(payload: str) -> dict:
    """Attempts to find key=value or key:value structures in a raw string payload."""
    fields = {}
    
    # Matches words followed by = or : and then non-whitespace chars
    # e.g., srcAddr=10.2.3.4 or dstPort:443
    pattern = r'([a-zA-Z0-9_\-\.]+)[=:]([^\s,\|]+)'
    
    for match in re.finditer(pattern, payload):
        key = match.group(1).strip()
        value = match.group(2).strip()
        # Avoid picking up weird artifacts, keep it to reasonable key names
        if len(key) > 1 and value:
            fields[key] = value
            
    return fields
