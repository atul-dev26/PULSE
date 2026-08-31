"""
Evidence Trust Score — Forensic confidence scoring for ULPF events.

This module computes a weighted trust score reflecting how much forensic
confidence can be placed in a given event's integrity.  The weights are
NOT arbitrary — each reflects a deliberate judgment about which checks
matter most in a digital-evidence chain-of-custody context.

Scoring philosophy
──────────────────
• **Raw hash is king (23 pts).**  If the raw evidence itself is tampered,
  every downstream artefact (parsing, normalization, enrichment) was
  derived from compromised input.  No amount of passing checks elsewhere
  can compensate, so raw_hash_verified carries the single-highest weight
  AND triggers a cascading penalty (see below).

• **Merkle proof is the batch-level seal (18 pts).**  A valid Merkle proof
  means the event's chain hash was committed into a tamper-evident tree
  alongside its peers.  This is the second-strongest guarantee because it
  provides *independent, batch-level* verification separate from the
  per-event raw hash.

• **Raw evidence preserved (12 pts).**  The file must still exist on disk.
  Without the physical artefact, re-verification is impossible — but this
  is a *precondition* check, not as strong as the hash itself.

• **Schema validated (12 pts).**  The normalized record's hash matches
  what was recorded at ingestion time.  A failure here with an intact raw
  hash suggests post-ingestion modification of the canonical record.

• **Blockchain anchor (12 pts).**  The batch's Merkle root was anchored
  to an external ledger.  In this MVP it's simulated, but the weight
  reflects its production importance as an externally-verifiable seal.

• **Provenance available (10 pts).**  Parser ID, version, and mapping
  version are recorded, enabling reproducibility.  Important for audit
  but not as critical as hash verification.

• **Parser identified (8 pts).**  We know *which* parser handled the
  event.  Lowest core weight because it's primarily informational — a
  known parser doesn't on its own guarantee correctness.

• **Threat intel bonus (+5, never penalised).**  In a production system,
  cross-referencing IOCs would add confidence.  Not yet implemented, so
  this is a bonus-only field that never drags the score down.

Cascading penalty
─────────────────
After computing raw_score from the weighted checks, a multiplicative
penalty is applied for integrity failures at critical layers:

  • raw_hash_verified == False  →  raw_score × 0.15
    Rationale: the root of trust is broken; the event is almost certainly
    unreliable regardless of other checks.

  • schema_validated == False (but raw is intact) →  raw_score × 0.55
    Rationale: original evidence is fine but the normalized record was
    altered; partial trust remains because the raw can be re-processed.

Renormalization for pending items
─────────────────────────────────
If an event hasn't been Merkle-batched yet, merkle_proof_verified and
blockchain_anchor_verified are excluded from BOTH the earned and possible
totals.  The score is then rescaled to a 95-point scale so a fresh event
isn't unfairly penalised for something that simply hasn't happened yet.
"""

import hashlib
import os
from sqlalchemy.orm import Session
from common.models import (
    RawEventRow,
    CanonicalEventRow,
    IntegrityRecordRow,
    BatchRow,
)
from integrity.chain import compute_normalized_hash
from integrity.merkle import compute_merkle_root

# ── Weight table ────────────────────────────────────────────────────────
BASE_WEIGHTS = {
    "raw_evidence_preserved": 12,       # Can we still access the physical artefact?
    "raw_hash_verified": 23,            # Highest weight: root of the trust chain — if raw
                                        # evidence integrity fails, nothing downstream can
                                        # be trusted regardless of other checks passing.
    "parser_identified": 8,             # Do we know which parser handled this event?
    "schema_validated": 12,             # Does the normalized record hash match?
    "provenance_available": 10,         # Are parser_id, versions, chain recorded?
    "merkle_proof_verified": 18,        # Second-highest: proves tamper-evidence at the
                                        # batch level, independent of raw hash.
    "blockchain_anchor_verified": 12,   # Was the batch anchored to an external ledger?
}
# Sums to 95.  Threat intel is a separate +5 bonus (see below), not a
# core weight — it's expected to be unavailable in this MVP and shouldn't
# drag the score down.

THREAT_INTEL_BONUS = 5

# Human-readable labels for the response.
_LABELS = {
    "raw_evidence_preserved": "Raw evidence preserved",
    "raw_hash_verified": "Raw hash verified",
    "parser_identified": "Parser identified",
    "schema_validated": "Schema validated",
    "provenance_available": "Provenance available",
    "merkle_proof_verified": "Merkle proof verified",
    "blockchain_anchor_verified": "Blockchain anchor verified",
}


def compute_trust_score(event_id: str, db: Session) -> dict:
    """Compute a forensic trust score for the given event.

    Returns the full response dict as specified by the API contract.
    Raises ``ValueError`` if the event_id is not found.
    """

    # ── Fetch rows ──────────────────────────────────────────────────
    raw_row = db.query(RawEventRow).filter(
        RawEventRow.event_id == event_id
    ).first()
    if not raw_row:
        raise ValueError("Event not found")

    integrity_row = db.query(IntegrityRecordRow).filter(
        IntegrityRecordRow.event_id == event_id
    ).first()

    canonical_row = db.query(CanonicalEventRow).filter(
        CanonicalEventRow.event_id == event_id
    ).first()

    # ── Run individual checks ───────────────────────────────────────
    checks: dict[str, bool | None] = {}

    # 1. raw_evidence_preserved — file still on disk?
    checks["raw_evidence_preserved"] = bool(
        raw_row.storage_uri and os.path.exists(raw_row.storage_uri)
    )

    # 2. raw_hash_verified — SHA-256 of file matches stored hash?
    if checks["raw_evidence_preserved"]:
        with open(raw_row.storage_uri, "rb") as f:
            disk_hash = hashlib.sha256(f.read()).hexdigest()
        stored_raw_hash = (
            integrity_row.raw_hash if integrity_row else raw_row.raw_sha256
        )
        checks["raw_hash_verified"] = (disk_hash == stored_raw_hash)
    else:
        checks["raw_hash_verified"] = False

    # 3. parser_identified
    checks["parser_identified"] = bool(
        integrity_row and integrity_row.parser_id
    )

    # 4. schema_validated — recompute normalized hash and compare
    if integrity_row and canonical_row:
        c_dict = {
            "event_id": canonical_row.event_id,
            "timestamp": canonical_row.timestamp,
            "source": canonical_row.source,
            "network": canonical_row.network,
            "security": canonical_row.security,
            "provenance": canonical_row.provenance,
            "enrichment": canonical_row.enrichment,
        }
        recomputed = compute_normalized_hash(c_dict)
        checks["schema_validated"] = (recomputed == integrity_row.normalized_hash)
    else:
        checks["schema_validated"] = False

    # 5. provenance_available
    checks["provenance_available"] = bool(
        integrity_row
        and integrity_row.parser_id
        and integrity_row.parser_version
        and integrity_row.mapping_version
    )

    # 6 & 7. Merkle / blockchain — determine "pending" status
    is_batched = bool(integrity_row and integrity_row.batch_id)

    if is_batched:
        batch = db.query(BatchRow).filter(
            BatchRow.batch_id == integrity_row.batch_id
        ).first()
        if batch:
            batch_records = (
                db.query(IntegrityRecordRow)
                .filter(IntegrityRecordRow.batch_id == integrity_row.batch_id)
                .order_by(IntegrityRecordRow.seq_id.asc())
                .all()
            )
            hashes = [r.chain_hash for r in batch_records]
            recomputed_merkle = compute_merkle_root(hashes)
            checks["merkle_proof_verified"] = (
                recomputed_merkle == batch.merkle_root
            )
            # Blockchain anchor: in production this would verify against the
            # ledger; in the MVP it's verified by the batch having a fake_tx_id.
            checks["blockchain_anchor_verified"] = bool(batch.fake_tx_id)
        else:
            checks["merkle_proof_verified"] = False
            checks["blockchain_anchor_verified"] = False
    else:
        # Not yet batched — these checks are not applicable.
        checks["merkle_proof_verified"] = None
        checks["blockchain_anchor_verified"] = None

    # Threat intel — not implemented in this MVP.
    threat_intel_available = False

    # ── Compute raw_score with renormalization ──────────────────────
    excluded_pending: list[str] = []
    earned = 0
    possible = 0

    for key, weight in BASE_WEIGHTS.items():
        if checks[key] is None:
            # Pending / not applicable — exclude from both sides.
            excluded_pending.append(key)
            continue
        possible += weight
        if checks[key]:
            earned += weight

    if possible > 0:
        raw_score = (earned / possible) * 95
    else:
        raw_score = 0.0

    # ── Cascading integrity penalty ─────────────────────────────────
    penalty_applied = "none"
    if not checks["raw_hash_verified"]:
        final_score = raw_score * 0.15
        penalty_applied = "raw_hash_failure_0.15x"
    elif not checks["schema_validated"]:
        final_score = raw_score * 0.55
        penalty_applied = "schema_failure_0.55x"
    else:
        final_score = raw_score

    raw_score_before_penalty = round(raw_score, 1)

    # ── Threat intel bonus ──────────────────────────────────────────
    threat_bonus = THREAT_INTEL_BONUS if threat_intel_available else 0
    final_score += threat_bonus

    # ── Clamp [0, 100] and round ────────────────────────────────────
    trust_score = int(round(max(0, min(100, final_score))))

    # ── Build checks list for response ──────────────────────────────
    checks_list = []
    for key, weight in BASE_WEIGHTS.items():
        entry: dict = {
            "label": _LABELS[key],
            "weight": weight,
            "passed": checks[key],
        }
        if checks[key] is None:
            entry["note"] = "Excluded: not yet batched"
        checks_list.append(entry)

    # Threat intel entry
    checks_list.append({
        "label": "Threat intelligence available",
        "weight": 0,
        "passed": threat_intel_available,
        "note": "Not implemented in this MVP (bonus only, not penalized)",
    })

    tampering_detected = (
        checks["raw_hash_verified"] is False
        or checks["schema_validated"] is False
        or checks.get("merkle_proof_verified") is False
    )

    return {
        "event_id": event_id,
        "trust_score": trust_score,
        "score_breakdown": {
            "raw_score_before_penalty": raw_score_before_penalty,
            "penalty_applied": penalty_applied,
            "threat_intel_bonus": threat_bonus,
            "excluded_pending_items": excluded_pending,
        },
        "checks": checks_list,
        "tampering_detected": tampering_detected,
    }
