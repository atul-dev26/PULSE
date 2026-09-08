"""
Correlation engine — lightweight entry point called after each ingest.
Runs all correlation rules for the given source_ip.
"""
from sqlalchemy.orm import Session
from correlation.rules import (
    check_brute_force,
    check_privilege_escalation_chain,
    check_port_scan,
)


def run_correlation(db: Session, source_ip: str | None) -> None:
    """
    Run all correlation rules for the given source_ip.
    Any incidents detected are added to the DB and committed.
    """
    if not source_ip:
        return

    rules = [
        check_brute_force,
        check_privilege_escalation_chain,
        check_port_scan,
    ]

    new_incidents = []
    for rule_fn in rules:
        try:
            incident = rule_fn(db, source_ip)
            if incident is not None:
                new_incidents.append(incident)
        except Exception as e:
            # Don't let correlation failures break ingestion
            print(f"[correlation] Rule {rule_fn.__name__} error: {e}")

    for inc in new_incidents:
        db.add(inc)

    if new_incidents:
        db.commit()
