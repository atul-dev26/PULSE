import os
from functools import lru_cache

try:
    import maxminddb
except ImportError:
    maxminddb = None

READER = None
DB_PATH = "GeoLite2-Country.mmdb"

if maxminddb and os.path.exists(DB_PATH):
    try:
        READER = maxminddb.open_database(DB_PATH)
    except Exception:
        READER = None

@lru_cache(maxsize=1024)
def get_country_code(ip_str: str) -> str:
    """Offline lookup of country code for a given IP."""
    if not READER or not ip_str:
        return None
    try:
        res = READER.get(ip_str)
        if res and 'country' in res and 'iso_code' in res['country']:
            return res['country']['iso_code']
    except Exception:
        pass
    return None
