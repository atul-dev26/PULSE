import time
from collections import deque
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

EVENTS_RECEIVED = Counter("events_received_total", "Total raw events received")
EVENTS_PARSED = Counter("events_parsed_total", "Total events successfully parsed", ["format"])
EVENTS_FAILED = Counter("events_failed_total", "Total events that failed and went to DLQ")
PARSE_LATENCY = Histogram("parse_latency_seconds", "Latency of the parsing & normalization stages")
EVENTS_PER_SECOND = Gauge("events_per_second", "Estimated events per second (gauge)")

_times = deque(maxlen=100)

def update_eps():
    now = time.time()
    _times.append(now)
    if len(_times) > 1:
        duration = _times[-1] - _times[0]
        if duration > 0:
            EVENTS_PER_SECOND.set(len(_times) / duration)

def get_observability_json() -> dict:
    format_counts = {}
    for sample in EVENTS_PARSED.collect()[0].samples:
        if sample.name == 'events_parsed_total':
            format_counts[sample.labels.get('format', 'unknown')] = sample.value
            
    latency_sum = 0
    latency_count = 0
    for sample in PARSE_LATENCY.collect()[0].samples:
        if sample.name == 'parse_latency_seconds_sum':
            latency_sum = sample.value
        elif sample.name == 'parse_latency_seconds_count':
            latency_count = sample.value
            
    events_received = sum(s.value for s in EVENTS_RECEIVED.collect()[0].samples if s.name == 'events_received_total')
    events_failed = sum(s.value for s in EVENTS_FAILED.collect()[0].samples if s.name == 'events_failed_total')
    events_per_sec = sum(s.value for s in EVENTS_PER_SECOND.collect()[0].samples if s.name == 'events_per_second')

    return {
        "events_received_total": events_received,
        "events_parsed_total": format_counts,
        "events_failed_total": events_failed,
        "parse_latency_seconds_sum": latency_sum,
        "parse_latency_seconds_count": latency_count,
        "events_per_second": events_per_sec
    }
