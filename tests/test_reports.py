import pytest

def test_reports_preview(test_client):
    # Ingest some events
    for i in range(3):
        res = test_client.post("/api/v1/ingest", json={
            "source_id": f"report-src-{i}",
            "transport": "HTTP",
            "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
        })
        assert res.status_code == 200

    # Test preview
    preview_res = test_client.get("/api/v1/reports/preview")
    assert preview_res.status_code == 200
    data = preview_res.json()
    assert data["total_events"] >= 3
    assert "severity_breakdown" in data
    assert "format_breakdown" in data
    assert "status_breakdown" in data

def test_reports_pdf(test_client):
    # Ingest some events
    for i in range(3):
        test_client.post("/api/v1/ingest", json={
            "source_id": f"pdf-src-{i}",
            "transport": "HTTP",
            "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
        })

    # Test PDF generation
    pdf_res = test_client.get("/api/v1/reports/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 0
    # Check PDF magic bytes
    assert pdf_res.content[:5] == b"%PDF-"

def test_reports_preview_with_filter(test_client):
    # Ingest events with a known source_id
    for i in range(2):
        test_client.post("/api/v1/ingest", json={
            "source_id": "filter-test-src",
            "transport": "HTTP",
            "payload": f'{{"src": "10.0.0.{i}", "dest": "10.0.0.99", "action": "allow"}}'
        })

    preview_res = test_client.get("/api/v1/reports/preview?source_id=filter-test-src")
    assert preview_res.status_code == 200
    data = preview_res.json()
    assert data["total_events"] >= 2
