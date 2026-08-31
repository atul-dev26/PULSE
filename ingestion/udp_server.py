import asyncio
import logging
from common.database import SessionLocal
from ingestion.splitter import split_payload
from ingestion.service import process_ingestion

logger = logging.getLogger(__name__)

class SyslogUDPReceiver(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        logger.info("UDP Syslog server started.")

    def datagram_received(self, data: bytes, addr):
        payload = data.decode('utf-8', errors='replace')
        ip_addr = addr[0]
        # Dispatch to an async task to avoid blocking the network loop
        asyncio.create_task(self.process_payload_in_thread(payload, ip_addr))

    async def process_payload_in_thread(self, payload: str, ip_addr: str):
        # Run synchronous DB/processing logic in a separate thread
        await asyncio.to_thread(self.process_payload, payload, ip_addr)

    def process_payload(self, payload: str, ip_addr: str):
        source_id = f"syslog-udp-{ip_addr}"
        transport_type = "syslog_udp"
        
        splits = split_payload(payload)
        db = SessionLocal()
        try:
            for item in splits:
                process_ingestion(db, source_id, transport_type, item)
        except Exception as e:
            logger.error(f"Error processing UDP packet: {e}")
        finally:
            db.close()

async def start_udp_server(host="127.0.0.1", port=5514):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogUDPReceiver(),
        local_addr=(host, port)
    )
    return transport, protocol
