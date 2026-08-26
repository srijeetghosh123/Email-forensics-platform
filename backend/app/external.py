"""
Live, server-side network checks: SPF (via DNS-over-HTTPS) and IP
geolocation. Running these server-side (rather than from the browser,
as the original client-only prototype did) avoids CORS fragility and
means the check isn't dependent on the analyst's own browser/network.
"""
import ipaddress
import requests

DNS_API = "https://dns.google/resolve"
GEO_API = "https://ipapi.co/{ip}/json/"


def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def check_spf(domain: str, ip: str) -> dict:
    """Mechanism-level SPF check only — does not recursively resolve
    include:/redirect=, and is not a full RFC 7208 evaluation."""
    if not domain or not ip:
        return {"found": None}
    try:
        resp = requests.get(DNS_API, params={"name": domain, "type": "TXT"}, timeout=5)
        data = resp.json()
        answers = [a["data"].strip('"') for a in data.get("Answer", [])]
        spf_record = next((a for a in answers if a.startswith("v=spf1")), None)
        if not spf_record:
            return {"found": False}
        mechanisms = [tok for tok in spf_record.split() if tok.startswith("ip4:")]
        mechanism_match = False
        for mech in mechanisms:
            val = mech.split(":", 1)[1]
            if "/" in val:
                mechanism_match = mechanism_match or ip_in_cidr(ip, val)
            else:
                mechanism_match = mechanism_match or (val == ip)
        return {
            "found": True,
            "record": spf_record,
            "mechanism_match": mechanism_match,
            "checked_mechanisms": len(mechanisms),
        }
    except requests.RequestException:
        return {"found": None, "error": True}


def geolocate(ip: str) -> dict:
    try:
        resp = requests.get(GEO_API.format(ip=ip), timeout=5)
        data = resp.json()
        if data.get("error"):
            raise ValueError("api error")
        return {
            "simulated": False,
            "ip": ip,
            "city": data.get("city", "—"),
            "region": data.get("region", "—"),
            "country": data.get("country_name", "—"),
            "isp": data.get("org", "—"),
            "timezone": data.get("timezone", "—"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
        }
    except Exception:
        # Deterministic offline fallback, clearly labeled, so the demo
        # never breaks if the free-tier geolocation API is unreachable.
        parts = [int(p) for p in ip.split(".")]
        seed = (parts[0] * 13 + parts[1] * 7 + parts[2] * 3 + parts[3]) % 6
        refs = [
            {"city": "Amsterdam", "region": "North Holland", "country": "Netherlands", "isp": "Datacenter / VPS hosting range", "timezone": "Europe/Amsterdam"},
            {"city": "Bucharest", "region": "Bucharest", "country": "Romania", "isp": "Bulletproof hosting range", "timezone": "Europe/Bucharest"},
            {"city": "Lagos", "region": "Lagos", "country": "Nigeria", "isp": "Consumer ISP range", "timezone": "Africa/Lagos"},
            {"city": "Hong Kong", "region": "Hong Kong", "country": "Hong Kong", "isp": "Cloud VPS range", "timezone": "Asia/Hong_Kong"},
            {"city": "Moscow", "region": "Moscow", "country": "Russia", "isp": "Datacenter range", "timezone": "Europe/Moscow"},
            {"city": "Panama City", "region": "Panama", "country": "Panama", "isp": "Offshore hosting range", "timezone": "America/Panama"},
        ]
        r = refs[seed]
        return {"simulated": True, "ip": ip, "lat": None, "lon": None, **r}
