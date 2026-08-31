import re

def parse_cef(payload: bytes) -> dict:
    text = payload.decode("utf-8").strip()
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    
    parts = text.split("|", 7)
    parsed = {}
    
    if len(parts) == 8:
        version_part = parts[0]
        parsed["cef_version"] = version_part.split(":")[1] if ":" in version_part else None
        parsed["vendor"] = parts[1]
        parsed["product"] = parts[2]
        parsed["device_version"] = parts[3]
        parsed["signature_id"] = parts[4]
        parsed["name"] = parts[5]
        parsed["severity"] = parts[6]
        
        extension = parts[7]
        # Extension is space separated kv pairs
        # Match word characters and basic value characters
        kv_matches = re.findall(r"([a-zA-Z0-9_\-]+)=([^\s]+)", extension)
        for k, v in kv_matches:
            if k not in parsed:
                parsed[k] = v
    else:
        parsed["message"] = text
        
    return parsed
