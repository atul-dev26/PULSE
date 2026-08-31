import json
import re
from pydantic import BaseModel
from typing import Optional

class DetectionResult(BaseModel):
    format: str
    vendor: Optional[str]
    parser_id: Optional[str]
    confidence: float

def detect(payload: bytes) -> DetectionResult:
    try:
        decoded_payload = payload.decode('utf-8').strip()
    except UnicodeDecodeError:
        decoded_payload = ""

    # Rule a: CEF
    if decoded_payload.startswith("CEF:"):
        return DetectionResult(
            format="CEF",
            vendor=None,
            parser_id="cef_parser",
            confidence=0.99
        )
        
    # Rule a2: LEEF
    if decoded_payload.startswith("LEEF:"):
        return DetectionResult(
            format="LEEF",
            vendor=None,
            parser_id="leef_parser",
            confidence=0.99
        )
    
    # Rule b: Syslog
    # match "<" followed by digits followed by ">" at string start
    if re.match(r"^<\d+>", decoded_payload):
        return DetectionResult(
            format="syslog",
            vendor=None,
            parser_id="syslog_parser",
            confidence=0.9
        )
    
    # Rule c: JSON
    if decoded_payload.startswith("{") or decoded_payload.startswith("["):
        try:
            json.loads(decoded_payload)
            return DetectionResult(
                format="json",
                vendor=None,
                parser_id="json_parser",
                confidence=0.95
            )
        except json.JSONDecodeError:
            pass

    # Rule d: Drain3 Fallback for unstructured textual logs
    if re.search(r'[A-Za-z0-9]', decoded_payload):
        return DetectionResult(
            format="drain3",
            vendor=None,
            parser_id="drain3_parser",
            confidence=0.1
        )

    # Rule e: Completely unparseable garbage
    return DetectionResult(
        format="unknown",
        vendor=None,
        parser_id=None,
        confidence=0.0
    )
