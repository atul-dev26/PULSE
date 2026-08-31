import json
import re
from typing import List

def split_payload(raw_text: str) -> List[str]:
    """
    Universally splits a raw payload into individual, independently-parseable logs.
    """
    raw_text = raw_text.strip()
    
    # Strategy a: Try parsing raw_text as JSON
    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            # It's a JSON array — return each element re-serialized
            return [json.dumps(item, separators=(',', ':')) for item in parsed]
        elif isinstance(parsed, dict):
            # It's a single JSON object — return as a single-item list
            return [raw_text]
    except json.JSONDecodeError:
        pass
        
    # Strategy b: Try NDJSON (newline-delimited JSON)
    lines = [line.strip() for line in raw_text.split('\n')]
    non_empty_lines = [line for line in lines if line]
    
    if len(non_empty_lines) > 1:
        all_json = True
        for line in non_empty_lines:
            try:
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    all_json = False
                    break
            except json.JSONDecodeError:
                all_json = False
                break
                
        if all_json:
            return non_empty_lines
            
    # Strategy c: Try multi-line structured formats (Syslog/CEF/LEEF)
    # Regexes for format signatures
    syslog_pattern = re.compile(r'^<\d+>')
    cef_pattern = re.compile(r'^CEF:')
    leef_pattern = re.compile(r'^LEEF:')
    
    def matches_signature(line: str) -> bool:
        return bool(syslog_pattern.match(line) or cef_pattern.match(line) or leef_pattern.match(line))

    if len(non_empty_lines) > 1:
        match_count = sum(1 for line in non_empty_lines if matches_signature(line))
        if match_count > 1:
            # MULTIPLE lines each independently match a signature, treat each line as its own log
            return non_empty_lines
            
    # Strategy d: If none of the above applied (e.g. single Syslog/CEF line, or unstructured text)
    # Return a single-item list containing the original raw_text unchanged.
    # Note: we return the original raw_text passed in (or stripped) so we don't break existing behaviour.
    return [raw_text]
