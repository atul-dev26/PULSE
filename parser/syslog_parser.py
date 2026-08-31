import re

# RFC3164 parsing regex
# e.g., <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
SYSLOG_REGEX = re.compile(r"^<(\d+)>([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$")

def parse_syslog(payload: bytes) -> dict:
    text = payload.decode("utf-8").strip()
    match = SYSLOG_REGEX.match(text)
    
    parsed = {}
    if not match:
        parsed["message"] = text
        return parsed
        
    priority_str, timestamp, hostname, application, message = match.groups()
    priority = int(priority_str)
    # severity = priority % 8
    severity_val = priority % 8
    
    # Basic severity mapping
    severity_map = {0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error", 4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug"}
    
    parsed["timestamp"] = timestamp
    parsed["hostname"] = hostname
    parsed["application"] = application
    parsed["severity"] = severity_map.get(severity_val, str(severity_val))
    parsed["message"] = message
    
    # Extract kv pairs from message
    # simple kv pattern: key=value
    kv_matches = re.findall(r"([a-zA-Z0-9_\-]+)=([a-zA-Z0-9_\-\.]+)", message)
    for k, v in kv_matches:
        if k not in parsed:
            parsed[k] = v
            
    return parsed
