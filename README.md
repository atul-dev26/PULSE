# PULSE — Universal Log Pre-Processing Framework (ULPF)

## 1. Project Information
Project Title: PULSE – Universal Log Pre-Processing Framework
PS ID: 26156
PS Title: Universal Log Pre-processing Framework (ULPF)
Category: Software
Theme: Cybersecurity and Blockchain

## 2. Problem Statement
Modern enterprises generate massive volumes of logs from firewalls, servers, VPNs, cloud platforms, and applications, in diverse formats such as Syslog, JSON, CEF, LEEF, and proprietary vendor schemas. This diversity forces security teams to hand-write and maintain source-specific parsers before data becomes usable for SIEM, data lake, or ML platforms — a slow, costly, and non-scalable process that also risks losing forensic integrity of the original evidence.

## 3. Proposed Solution
PULSE ingests security logs from any source, in any format, and automatically detects, parses, and normalizes them into a single unified, OCSF-aligned schema — while preserving the original raw evidence losslessly. Every event is cryptographically hashed, chained, and anchored via Merkle proofs, producing a computed Evidence Trust Score that makes tampering instantly detectable. When an unrecognized vendor source is encountered, PULSE automatically suggests a confidence-scored field mapping instead of requiring manual parser development. Related events are further correlated into detected incidents mapped to MITRE ATT&CK techniques, and normalized output is exportable directly to SIEM and data lake systems (CSV/JSON/CEF).

## 4. Key Features
- Universal log ingestion (JSON, Syslog, CEF, LEEF, and unstructured formats via Drain3 fallback)
- Automatic format detection and multi-log-per-request splitting (JSON arrays, NDJSON, multi-line Syslog)
- Real native UDP Syslog listener, in addition to REST ingestion
- Normalization into a unified, OCSF-aligned schema
- Cryptographic integrity: SHA-256 hashing, hash chain, Merkle tree batching, tamper-evident verification
- Self-learning field-mapping onboarding for new/unrecognized log sources, with confidence scoring
- Computed Evidence Trust Score (weighted, documented formula) per event
- Chain-of-custody certificate export (self-verifying, tamper-evident document)
- Rule-based attack correlation engine mapped to MITRE ATT&CK techniques
- Dead Letter Queue for failed/unparseable events (raw evidence always preserved)
- SIEM/Data Lake export (CSV, JSON, CEF re-emission)
- JWT-based authentication securing all API access
- Live dashboard, event investigation console, analytics/incident view, and interactive playground for testing arbitrary log input
- Fully containerized (Docker/Docker Compose), designed for air-gapped deployment

## 5. Technology Stack
- Frontend: HTML, CSS, JavaScript, Chart.js
- Backend: Python, FastAPI, SQLAlchemy, Uvicorn, Pydantic
- Log Parsing: Custom format detector, Drain3 (unstructured log template mining)
- Security: SHA-256, Merkle trees, JWT (bcrypt password hashing)
- Database: SQLite (MVP) — architected for direct migration to PostgreSQL at scale
- Storage: Local filesystem (raw evidence), append-only ledger (integrity anchor)
- Testing: Pytest
- Deployment: Docker, Docker Compose

## 6. Architecture
See `docs/architecture.md`.
Log Sources (Firewall/Server/VPN/Cloud)
|
v
Ingestion Gateway (REST API + UDP Syslog Listener)
|
v
Format Detection & Splitter
|
v
Parser Engine (JSON / Syslog / CEF / LEEF / Drain3)
|
v
Normalization Engine (OCSF-aligned Schema)
|
+----> Enrichment (IP classification)
|
+----> Correlation Engine (MITRE ATT&CK mapping)
|
v
Integrity Layer (Hash Chain -> Merkle Tree -> Anchor Ledger)
|
v
Storage (SQLite metadata + Local raw evidence store)
|
v
REST API -> Dashboard / SIEM Export / Data Lake Export


## 7. Repository Structure

PULSE-ULPF/
├── README.md
├── SUBMISSION_GUIDE.md
├── submission/
│ ├── PRESENTATION.md
│ └── DEMO.md
├── api/
├── ingestion/
├── detection/
├── parser/
├── normalization/
├── enrichment/
├── integrity/
├── onboarding/
├── correlation/
├── static/
├── tests/
├── docs/
│ └── architecture.md
├── assets/
│ └── screenshots/
│ └── README.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .gitignore
└── LICENSE


### What goes where?
| Item | Location |
|---|---|
| Source code | `api/`, `ingestion/`, `detection/`, `parser/`, `normalization/`, `enrichment/`, `integrity/`, `onboarding/`, `correlation/`, `static/` |
| Architecture / technical documentation | `docs/` |
| Project screenshots | `assets/screenshots/` |
| Final PPT / presentation | `submission/` |
| Demo video link | `submission/DEMO.md` |
| Project overview | `README.md` |

## 8. Final Presentation
See `submission/PRESENTATION.md` for the link/file.

## 9. Demo Video
See `submission/DEMO.md` for the link.

## 10. Screenshots / Prototype Photos
See `assets/screenshots/`.

## 11. Installation
```bash
git clone https://github.com/atul-dev26/PULSE
cd PULSE-ULPF
pip install -r requirements.txt
```

Or, using Docker (recommended):
```bash
docker-compose up --build
```

## 12. Run
```bash
python -m uvicorn main:app --reload
```
Then open:
- Dashboard: `http://127.0.0.1:8000/dashboard`
- API Docs: `http://127.0.0.1:8000/docs`

Default login: `admin` / `changeme123` (change before any real deployment).

## 13. Future Scope
- Migrate metadata storage from SQLite to PostgreSQL, and raw evidence to MinIO/S3, for production-scale deployment
- Replace the local append-only anchor ledger with a real Hyperledger Fabric permissioned blockchain network
- Introduce Apache Kafka for horizontal, streaming ingestion at billions-of-events/day scale
- Add OpenSearch/Elasticsearch for full-text search and analytics over normalized events at scale
- Expand correlation rules with supervised ML models trained on labeled incident data
- Integrate with organizational SSO/IAM for production-grade role-based access control
- Full OCSF JSON-schema validation (current implementation is OCSF-aligned; full spec-validated compliance is a scoped extension)

## Important
Before submission, ensure the repository is accessible to reviewers. Do not upload passwords, API keys, access tokens, `.env` files containing secrets, or other confidential credentials. The default seeded admin password above is for local development only — never commit real credentials.
