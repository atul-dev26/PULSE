import pytest
import json
import time

def test_export_csv_headers_and_row_count(test_client, auth_headers):
    # Ensure event ingestion
    res = test_client.post("/api/v1/ingest", json={"source_id": "export-csv-test", "transport": "HTTP", "payload": '{"src": "10.0.0.1", "dest": "10.0.0.2", "action": "allow"}'})
    assert res.status_code == 200

    # Test the export endpoint for CSV format
    res = test_client.get("/api/v1/export?format=csv&source_id=export-csv-test", headers=auth_headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "text/csv"
    
    # Parse CSV content
    lines = res.content.decode("utf-8").strip().split("\r\n")
    assert len(lines) >= 2 # Header + at least one row
    
    # Check that headers are correct (flat, consistent canonical schema fields)
    expected_headers = "event_id,timestamp,source,source_ip,destination_ip,source_port,destination_port,protocol,action,severity,status,trust_score,format,parser_id"
    assert lines[0] == expected_headers

def test_export_json_valid_and_filtered(test_client, auth_headers):
    # Ensure event ingestion
    res = test_client.post("/api/v1/ingest", json={"source_id": "export-json-test", "transport": "HTTP", "payload": '{"src": "192.168.1.1", "dest": "192.168.1.2", "action": "block"}'})
    assert res.status_code == 200

    # Test JSON export with filtering
    res = test_client.get("/api/v1/export?format=json&source_id=export-json-test", headers=auth_headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/json"
    
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    
    # Check consistent JSON structure mapping to canonical fields
    event = data[0]
    assert "event_id" in event
    assert "timestamp" in event
    assert event["source"] == "export-json-test"
    assert "source_ip" in event
    assert "destination_ip" in event

def test_export_cef_cross_format_reemission(test_client, auth_headers):
    # Ingest a JSON log
    payload = {"src": "172.16.0.1", "dest": "172.16.0.2", "action": "drop", "severity": "high"}
    res = test_client.post("/api/v1/ingest", json={"source_id": "export-cef-test", "transport": "HTTP", "payload": json.dumps(payload)})
    assert res.status_code == 200

    # Re-emit as CEF
    res = test_client.get("/api/v1/export?format=cef&source_id=export-cef-test", headers=auth_headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "text/plain; charset=utf-8"
    
    # Check CEF format
    lines = res.content.decode("utf-8").strip().split("\n")
    assert len(lines) >= 1
    
    cef_line = lines[0]
    # Header format: CEF:0|ULPF|Event|1.0|{parser_id}|{action}|{severity_num}|
    assert cef_line.startswith("CEF:0|ULPF|Event|1.0|")
    
    # Check for fields mapped into CEF extensions
    assert "src=172.16.0.1" in cef_line
    assert "dst=172.16.0.2" in cef_line
    assert "cs1=SUCCESS cs1Label=Status" in cef_line

def test_export_preview(test_client, auth_headers):
    # Ensure event ingestion
    res = test_client.post("/api/v1/ingest", json={"source_id": "export-preview-test", "transport": "HTTP", "payload": '{"src": "10.0.0.1", "dest": "10.0.0.2", "action": "allow"}'})
    assert res.status_code == 200

    res = test_client.get("/api/v1/export/preview?source_id=export-preview-test", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_matching" in data
    assert data["total_matching"] >= 1
