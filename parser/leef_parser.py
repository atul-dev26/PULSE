import re

def parse_leef(payload: bytes) -> dict:
    text = payload.decode("utf-8").strip()
    # LEEF:Version|Vendor|Product|Version|EventID|Extension
    
    parts = text.split("|", 5)
    parsed = {}
    
    if len(parts) == 6:
        version_part = parts[0]
        parsed["leef_version"] = version_part.split(":")[1] if ":" in version_part else None
        parsed["vendor"] = parts[1]
        parsed["product"] = parts[2]
        parsed["device_version"] = parts[3]
        parsed["event_id"] = parts[4]
        
        extension = parts[5]
        
        # LEEF extensions are typically tab-separated key=value pairs, though
        # sometimes spaces depending on the exact dialect/syslog wrapper. 
        # We look for key=value delimited by either tabs or spaces.
        kv_matches = re.findall(r"([a-zA-Z0-9_\-]+)=([^\t]+)(?:\t|$)", extension)
        
        # Fallback to spaces if no tabs are found
        if not kv_matches and " " in extension and "\t" not in extension:
            kv_matches = re.findall(r"([a-zA-Z0-9_\-]+)=([^\s]+)", extension)
            
        for k, v in kv_matches:
            if k not in parsed:
                parsed[k] = v.strip()
    else:
        parsed["message"] = text
        
    return parsed
