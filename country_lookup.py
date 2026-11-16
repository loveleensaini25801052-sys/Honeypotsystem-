import json
import urllib.request
import socket

# In-memory cache for IP lookups to avoid repeated network calls
_geo_cache = {}

def is_private_ip(ip):
    """Check if an IP address belongs to a private network or localhost."""
    if not ip or ip == "Unknown":
        return True
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        try:
            parts = ip.split(".")
            if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                return True
        except ValueError:
            pass
    return False

def get_ip_details(ip):
    """
    Returns a tuple of (country, city, country_code) for a given IP.
    Handles private lab networks and public IP geolocation lookup.
    """
    if not ip or ip == "Unknown":
        return ("Unknown", "Unknown", "XX")

    if is_private_ip(ip):
        return ("Local Cyber Lab", "Internal Subnet", "LAB")

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        # Use ip-api.com free JSON endpoint with a short 2-second timeout
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,countryCode"
        req = urllib.request.Request(url, headers={'User-Agent': 'HoneypotSOC/2.0'})
        with urllib.request.urlopen(req, timeout=2.0) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                country = data.get("country", "Unknown")
                city = data.get("city", "Unknown")
                code = data.get("countryCode", "UN")
                result = (country, city, code)
                _geo_cache[ip] = result
                return result
    except Exception:
        pass

    result = ("External Public IP", "Unknown City", "NET")
    _geo_cache[ip] = result
    return result

def get_country(ip):
    """
    Backward-compatible helper that returns the country string.
    """
    country, _, _ = get_ip_details(ip)
    return country