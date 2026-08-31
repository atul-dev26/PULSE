"""
benchmarks/run_benchmark.py
---------------------------
Sequential ingestion benchmark for the ULPF FastAPI server.

Usage
-----
    python benchmarks/run_benchmark.py              # default 1000 events
    python benchmarks/run_benchmark.py --n 500
    python benchmarks/run_benchmark.py --n 200 --url http://127.0.0.1:8000

The script posts N synthetic events, times the whole run, then prints a
summary table.  Run from the project root (ulpf/).
"""
import io

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request

# ── synthetic data pools ──────────────────────────────────────────────────────

ACTIONS   = ["ALLOW", "DENY", "DROP", "REJECT", "ACCEPT", "BLOCK"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFORMATIONAL"]
VENDORS   = ["Cisco", "Palo Alto", "Fortinet", "CheckPoint", "Juniper", "SonicWall"]


def _rand_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_port() -> int:
    return random.choice([22, 80, 443, 8080, 3389, 53, 25, 110, 3306, 5432, 1433])


# ── format generators ─────────────────────────────────────────────────────────

def make_json_payload() -> str:
    return json.dumps({
        "timestamp": f"2026-08-29T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z",
        "src_ip":    _rand_ip(),
        "dst_ip":    _rand_ip(),
        "dst_port":  _rand_port(),
        "action":    random.choice(ACTIONS),
        "severity":  random.choice(SEVERITIES),
        "vendor":    random.choice(VENDORS),
    })


def make_syslog_payload() -> str:
    pri = random.randint(0, 191)
    host = f"fw-{random.randint(1, 99):02d}.corp"
    proc = random.choice(["kernel", "sshd", "firewalld", "audit"])
    src  = _rand_ip()
    dst  = _rand_ip()
    act  = random.choice(ACTIONS)
    sev  = random.choice(SEVERITIES)
    return f"<{pri}>Aug 29 {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} {host} {proc}: src={src} dst={dst} action={act} severity={sev}"


def make_cef_payload() -> str:
    vendor  = random.choice(VENDORS)
    product = random.choice(["NGFW", "IDS", "UTM", "VPN"])
    version = f"{random.randint(1,9)}.{random.randint(0,9)}"
    sig     = random.randint(1000, 9999)
    sev_num = random.randint(0, 10)
    src     = _rand_ip()
    dst     = _rand_ip()
    act     = random.choice(ACTIONS)
    sev     = random.choice(SEVERITIES)
    return (
        f"CEF:0|{vendor}|{product}|{version}|{sig}|Firewall Event|{sev_num}|"
        f"src={src} dst={dst} act={act} severity={sev}"
    )


_FORMATS = [
    ("json",   make_json_payload),
    ("syslog", make_syslog_payload),
    ("cef",    make_cef_payload),
]


def generate_events(n: int) -> list[dict]:
    """Return a list of n dicts ready to be POST-ed as ingest requests."""
    events = []
    for i in range(n):
        fmt, generator = _FORMATS[i % len(_FORMATS)]   # round-robin + some randomness
        if random.random() < 0.15:
            fmt, generator = random.choice(_FORMATS)   # 15 % chance of random pick
        events.append({
            "fmt": fmt,
            "body": {
                "source_id": f"bench-{fmt}-{i:05d}",
                "transport": "benchmark",
                "payload":   generator(),
            },
        })
    return events


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def check_server(base_url: str) -> bool:
    """Return True if the server is responding, print a warning and return False otherwise."""
    try:
        urllib.request.urlopen(f"{base_url}/api/v1/stats", timeout=5)
        return True
    except urllib.error.URLError as exc:
        print(f"\n! WARNING: Cannot reach ULPF server at {base_url}")
        print(f"   Reason : {exc.reason}")
        print("   Make sure `python -m uvicorn main:app --reload` is running.\n")
        return False
    except Exception as exc:
        print(f"\n! WARNING: Unexpected error contacting {base_url}: {exc}\n")
        return False


def fetch_stats(base_url: str) -> dict:
    try:
        r = urllib.request.urlopen(f"{base_url}/api/v1/stats", timeout=10)
        return json.loads(r.read())
    except Exception:
        return {}


def post_event(base_url: str, body: dict) -> tuple[int, str]:
    """POST one ingest request; return (status_code, format_detected_or_error)."""
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        f"{base_url}/api/v1/ingest",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        r    = urllib.request.urlopen(req, timeout=30)
        resp = json.loads(r.read())
        return r.status, resp.get("format", "unknown")
    except urllib.error.HTTPError as exc:
        return exc.code, "error"
    except Exception as exc:
        return 0, f"conn_error: {exc}"


# ── main ──────────────────────────────────────────────────────────────────────

def run(n: int, base_url: str) -> None:
    print(f"\n{'='*62}")
    print(f"  ULPF Ingestion Benchmark")
    print(f"  Target  : {base_url}/api/v1/ingest")
    print(f"  Events  : {n:,}")
    print(f"{'='*62}\n")

    if not check_server(base_url):
        sys.exit(1)

    # Snapshot stats before the run so we can compute deltas
    stats_before = fetch_stats(base_url)
    fmt_before   = stats_before.get("events_by_format", {})

    events = generate_events(n)

    # ── ingest loop ──
    sent_by_fmt: dict[str, int] = {}          # what we sent
    detected_by_fmt: dict[str, int] = {}      # what the server echoed back
    successes = 0
    failures  = 0
    errors: list[str] = []

    print("  Posting events...  (dots = 50 events each)")
    t_start = time.perf_counter()

    for idx, ev in enumerate(events, 1):
        status, detected = post_event(base_url, ev["body"])
        sent_by_fmt[ev["fmt"]] = sent_by_fmt.get(ev["fmt"], 0) + 1

        if status == 200:
            successes += 1
            detected_by_fmt[detected] = detected_by_fmt.get(detected, 0) + 1
        else:
            failures += 1
            errors.append(f"  [{idx:5d}] HTTP {status} — {detected}")

        if idx % 50 == 0:
            print(".", end="", flush=True)

    t_end = time.perf_counter()
    elapsed = t_end - t_start

    print()  # newline after dots

    # Snapshot stats after
    stats_after  = fetch_stats(base_url)
    fmt_after    = stats_after.get("events_by_format", {})

    # Compute per-format delta (new events added during this run)
    all_fmts = sorted(set(list(fmt_before) + list(fmt_after)))
    fmt_delta: dict[str, int] = {
        f: fmt_after.get(f, 0) - fmt_before.get(f, 0)
        for f in all_fmts
    }

    # ── print summary ──
    eps = successes / elapsed if elapsed > 0 else float("inf")

    print(f"\n{'-'*62}")
    print(f"  RESULTS")
    print(f"{'-'*62}")
    print(f"  Total sent        : {n:>8,}")
    print(f"  Successes (HTTP 200): {successes:>6,}")
    print(f"  Failures          : {failures:>8,}")
    print(f"  Total time        : {elapsed:>8.2f} s")
    print(f"  Events / second   : {eps:>8.1f} EPS")

    print(f"\n  {'Format':<12}  {'Sent':>8}  {'Server detected':>16}")
    print(f"  {'-'*12:<12}  {'-'*8:>8}  {'-'*15:>16}")
    all_row_fmts = sorted(set(list(sent_by_fmt) + list(fmt_delta)))
    for fmt in all_row_fmts:
        s = sent_by_fmt.get(fmt, 0)
        d = fmt_delta.get(fmt, 0)
        match_marker = "OK" if s > 0 and abs(s - d) <= max(5, int(s * 0.02)) else ("" if s == 0 else "WARN")
        print(f"  {fmt:<12}  {s:>8,}  {d:>16,}  {match_marker}")

    if failures and errors:
        print(f"\n  First {min(5, len(errors))} failure(s):")
        for e in errors[:5]:
            print(e)

    print(f"\n  Server totals after run:")
    print(f"    total_events     : {stats_after.get('total_events', '?')}")
    print(f"    total_normalized : {stats_after.get('total_normalized', '?')}")
    print(f"    total_batches    : {stats_after.get('total_batches', '?')}")
    print(f"{'='*62}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ULPF sequential ingestion benchmark",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--n",   type=int, default=1000, help="Number of events to ingest")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000", help="Base URL of ULPF server")
    args = parser.parse_args()

    run(n=args.n, base_url=args.url.rstrip("/"))


if __name__ == "__main__":
    main()
