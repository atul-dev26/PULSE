import ipaddress

def classify_ip(ip_str: str) -> str:
    """Classify an IP string into 'private', 'public', 'loopback', or 'invalid'."""
    if not ip_str:
        return "invalid"
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return "private"
        if ip.is_loopback:
            return "loopback"
        # Optional: check for multicast, reserved, etc.
        # But for MVP, everything else is public
        return "public"
    except ValueError:
        return "invalid"
