import pytest
import socket
import time
from common.models import RawEventRow, CanonicalEventRow

def test_udp_syslog_ingestion(test_client, setup_db):
    """
    Test that a raw Syslog message sent via genuine UDP socket
    ends up fully processed alongside REST HTTP ones.
    Uses port 5515 because that's configured via conftest.py's UDP_PORT 
    to not collide with the dev server on 5514.
    """
    from common.database import SessionLocal
    
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 5515
    msg = b"<34>Oct 11 22:14:15 test-udp-fw kernel: MSG"
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    db_before = SessionLocal()
    count_before = db_before.query(RawEventRow).count()
    db_before.close()

    # Send packet
    sock.sendto(msg, (TARGET_IP, TARGET_PORT))
    sock.close()
    
    # Wait lightly for background processing
    time.sleep(0.5)
    
    db_after = SessionLocal()
    # Check that event was stored and assigned syslog_udp transport
    raw = db_after.query(RawEventRow).filter(RawEventRow.transport == "syslog_udp").first()
    
    assert raw is not None, "UDP Syslog was not stored in RawEventRow"
    
    canonical = db_after.query(CanonicalEventRow).filter(CanonicalEventRow.event_id == raw.event_id).first()
    assert canonical is not None, "UDP Syslog was not normalized"
    
    db_after.close()
