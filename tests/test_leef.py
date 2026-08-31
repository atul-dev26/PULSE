"""Tests for LEEF format parsing and detection."""

import pytest
from detection.detector import detect
from parser.leef_parser import parse_leef

def test_leef_parsing():
    """Verify parsing a properly formatted LEEF payload."""
    payload = b"LEEF:1.0|IBM|QRadar|1.0|4624|src=10.0.0.1\tdst=10.0.0.2\tsev=5\tact=login"
    
    # 1. Detection
    det = detect(payload)
    assert det.format == "LEEF"
    assert det.parser_id == "leef_parser"
    
    # 2. Parsing
    parsed = parse_leef(payload)
    assert parsed["leef_version"] == "1.0"
    assert parsed["vendor"] == "IBM"
    assert parsed["product"] == "QRadar"
    assert parsed["device_version"] == "1.0"
    assert parsed["event_id"] == "4624"
    assert parsed["src"] == "10.0.0.1"
    assert parsed["dst"] == "10.0.0.2"
    assert parsed["sev"] == "5"
    assert parsed["act"] == "login"

def test_leef_vs_cef_detection():
    """Confirm LEEF is not misdetected as CEF, and vice versa."""
    leef_payload = b"LEEF:2.0|Vendor|Product|2.0|EventID|src=1.1.1.1 dst=2.2.2.2"
    cef_payload = b"CEF:0|Vendor|Product|2.0|EventID|Name|1|src=1.1.1.1 dst=2.2.2.2"
    
    det_leef = detect(leef_payload)
    assert det_leef.format == "LEEF"
    assert det_leef.parser_id == "leef_parser"
    
    det_cef = detect(cef_payload)
    assert det_cef.format == "CEF"
    assert det_cef.parser_id == "cef_parser"
