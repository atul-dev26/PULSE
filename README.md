# ULPF - Universal Log Pre-Processing Framework

The **Universal Log Pre-Processing Framework (ULPF)** is a vendor-neutral log processing pipeline designed to ingest, normalize, and secure audit trails at scale. It normalizes disparate log formats into a canonical schema while applying a robust cryptographic integrity and tamper-evidence layer, ensuring that critical security data remains provably unmodified from ingestion to analysis.

## Setup Instructions

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the server (development mode):
   ```bash
   python -m uvicorn main:app --reload
   ```

### Option B: Docker (Containerized / Air-gapped / Cloud Deployment)
1. Build and run the container using Docker Compose:
   ```bash
   docker-compose up --build
   ```
   Add `-d` to run in detached (background) mode.

2. The application will be accessible at:
   - **Dashboard**: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)
   - **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

3. To stop and clean up:
   ```bash
   docker-compose down           # Stops containers (keeps data volumes)
   docker-compose down -v        # Stops containers AND deletes data volumes
   ```

### Persistent Data Paths (inside the container)
When deploying to a hosting platform (Render, Railway, etc.), mount a persistent disk at these paths:

| Data | Container Path | Description |
|------|---------------|-------------|
| SQLite Database | `/app/data/ulpf.db` | Main application database |
| Raw Evidence | `/app/raw/` | Raw log payloads (`.raw` files) |
| Anchor Log | `/app/integrity/anchor_log.jsonl` | Mock blockchain anchor records |

## Quick Links

- **Live Dashboard**: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
- **API Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## What's Implemented in this MVP

- **Auto-Detection Ingestion**: Handles raw JSON, Syslog, and CEF ingestion over REST, seamlessly detecting formats on the fly.
- **Canonical Normalization**: Standardizes divergent incoming events into a unified, predictable canonical schema.
- **Cryptographic Fingerprinting**: Calculates SHA-256 hashes for both the standalone raw evidence payloads and the normalized records.
- **Cryptographic Hash Chaining**: Links sequential events together in an unbroken chain mathematically.
- **Merkle Tree Batching**: Batches events into Merkle trees for efficient bulk validation.
- **Tamper Verification**: A robust `/verify` system to mathematically prove end-to-end log custody.
- **Mock Blockchain Anchor**: A simulated anchor mechanism. *(Note: This is a stand-in for Hyperledger Fabric in this MVP. For production, Merkle roots would be committed as actual transactions to a Fabric ledger).*
- **Real-Time Dashboard**: A fast, zero-reload graphical UI to monitor events and manually trigger verifications.

## How to Demo Tamper Detection

1. Start the server and navigate to the **Live Dashboard**.
2. Run the benchmark or seed script to **ingest a log** (e.g., `python benchmarks/run_benchmark.py --n 1`).
3. Note the newly ingested log's `event_id` in the dashboard table.
4. Open the raw storage file locally at `raw/<event_id>.raw` using any text editor.
5. **Change a single byte** in the file (e.g., alter an IP address or an action) and **Save**.
6. Back on the dashboard, click the **Verify** button for that exact row.
7. Watch the verification instantly fail and output a red **TAMPERING DETECTED** badge.

## Architecture Decisions for this MVP

To fit within the rapid constraints of a hackathon timeline while effectively proving the core cryptographic and normalization concepts, we substituted heavy enterprise infrastructure with simpler agile equivalents:

- **Kafka** (message broker) was swapped for synchronous REST API boundaries.
- **MinIO/S3** (raw evidence object store) was swapped for the local filesystem (`/raw`).
- **PostgreSQL / OpenSearch** (indexed search & analytical storage) was swapped for a standardized SQLite database (`ulpf.db`).
- **Hyperledger Fabric** (immutable ledger) was swapped for a mock anchor layer appending to `anchor_log.jsonl`.

The full production-grade design utilizing the complete enterprise tech stack is available and mapped out in the project's HLD and LLD documentation.
