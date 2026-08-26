"""
Header forensics, content heuristics, and relay-chain reconstruction for
raw email source. Server-side so it isn't limited by browser CORS/sandbox
constraints (relevant for the live SPF check in spf.py).
"""
import re

PRIVATE_IP_RE = re.compile(
    r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)"
)
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s)>\]\"']+")
ANCHOR_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
ATTACHMENT_RE = re.compile(r'filename\*?=["\']?[^;\n"\']*?\.([a-zA-Z0-9]+)["\']?', re.IGNORECASE)
RECEIVED_RE = re.compile(r"^Received:.*(?:\n[ \t]+.*)*", re.IGNORECASE | re.MULTILINE)

URGENT_WORDS = [
    "urgent", "verify your account", "suspended", "act now", "click here immediately",
    "confirm your identity", "limited time", "password will expire", "unusual activity",
    "wire transfer", "gift card", "final notice", "restricted access", "update your payment",
    "security alert",
]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"]
DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "ps1", "docm", "xlsm", "pptm", "iso", "lnk"}


def get_header(raw: str, name: str):
    m = re.search(rf"^{re.escape(name)}:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def domain_of(addr: str | None):
    if not addr:
        return None
    m = re.search(r"@([a-zA-Z0-9.\-]+)", addr)
    return m.group(1).lower() if m else None


def split_email(raw: str):
    parts = re.split(r"\n\s*\n", raw, maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return raw, ""


def parse_received_chain(header_block: str):
    matches = RECEIVED_RE.findall(header_block)
    hops = []
    for m in matches:
        ip_match = re.search(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", m)
        host_match = re.search(r"from\s+([a-zA-Z0-9.\-]+)", m, re.IGNORECASE)
        ip = ip_match.group(1) if ip_match else None
        hops.append({
            "host": host_match.group(1) if host_match else "(unknown host)",
            "ip": ip,
            "is_private": bool(PRIVATE_IP_RE.match(ip)) if ip else True,
        })
    hops.reverse()  # Received headers are prepended -> reverse = chronological, origin first
    return hops


def check_anchor_mismatch(body: str):
    flags = []
    for href, visible_raw in ANCHOR_RE.findall(body):
        visible = re.sub(r"<[^>]+>", "", visible_raw).strip()
        looks_like_url = bool(re.match(r"^(https?://|www\.)", visible, re.IGNORECASE)) or bool(
            re.search(r"\.[a-z]{2,}/", visible)
        )
        if looks_like_url:
            href_domain_m = re.search(r"https?://([^/]+)", href)
            vis_domain_m = re.search(r"(?:https?://)?([^/\s]+)", visible)
            href_domain = href_domain_m.group(1) if href_domain_m else href
            vis_domain = vis_domain_m.group(1) if vis_domain_m else visible
            if href_domain.lower() != vis_domain.lower():
                flags.append(
                    f'Cloaked link: text shown to reader is "{visible}" but the link actually points to {href_domain}.'
                )
    return flags


def check_attachments(raw: str):
    flags = []
    for ext in ATTACHMENT_RE.findall(raw):
        if ext.lower() in DANGEROUS_EXT:
            flags.append(f"Attachment with high-risk extension detected: .{ext.lower()}")
    return flags


def analyze_email(raw: str, nb_result: dict):
    header_block, body = split_email(raw)

    from_addr = get_header(header_block, "From")
    reply_to = get_header(header_block, "Reply-To")
    return_path = get_header(header_block, "Return-Path")
    subject = get_header(header_block, "Subject")
    auth_results = get_header(header_block, "Authentication-Results")

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_to)
    return_domain = domain_of(return_path)

    score = 0
    indicators = []

    if reply_domain and from_domain and reply_domain != from_domain:
        score += 25
        indicators.append({"sev": "high", "text": f"Reply-To domain ({reply_domain}) does not match From domain ({from_domain}) — classic redirection-for-response pattern."})
    if return_domain and from_domain and return_domain != from_domain:
        score += 15
        indicators.append({"sev": "med", "text": f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})."})

    if auth_results:
        if re.search(r"spf=fail", auth_results, re.IGNORECASE):
            score += 20
            indicators.append({"sev": "high", "text": "Authentication-Results header reports SPF=fail (as evaluated by the receiving server)."})
        if re.search(r"dkim=none|dkim=fail", auth_results, re.IGNORECASE):
            score += 12
            indicators.append({"sev": "med", "text": "DKIM signature missing or invalid per Authentication-Results header."})
        if re.search(r"dmarc=fail", auth_results, re.IGNORECASE):
            score += 18
            indicators.append({"sev": "high", "text": "DMARC alignment failed per Authentication-Results header."})
    else:
        score += 5
        indicators.append({"sev": "low", "text": "No Authentication-Results header present to verify sender."})

    body_lower = body.lower()
    hit_words = [w for w in URGENT_WORDS if w in body_lower]
    if hit_words:
        score += min(20, len(hit_words) * 5)
        indicators.append({"sev": "high" if len(hit_words) >= 3 else "med", "text": f"Urgency/pressure language detected: {', '.join(hit_words[:5])}."})

    # AI classifier contribution
    prob = nb_result["probability_phishing"]
    if prob >= 0.5:
        score += round((prob - 0.5) * 40)
        indicators.append({"sev": "high" if prob >= 0.75 else "med", "text": f"Naive Bayes text classifier estimates {round(prob*100)}% probability of phishing based on message wording."})

    for msg in check_anchor_mismatch(body):
        score += 15
        indicators.append({"sev": "high", "text": msg})

    for msg in check_attachments(raw):
        score += 15
        indicators.append({"sev": "high", "text": msg})

    urls = URL_RE.findall(body)
    ip_literal_link = None
    for u in urls:
        if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u):
            score += 20
            ip_literal_link = u
            indicators.append({"sev": "high", "text": f"Link points to a raw IP address rather than a domain: {u}"})
        for s in SHORTENERS:
            if s in u:
                score += 10
                indicators.append({"sev": "med", "text": f"Link uses a URL shortener ({s}), obscuring the true destination."})
    if not urls:
        indicators.append({"sev": "low", "text": "No embedded links found in message body."})

    score = min(100, score)

    relay_hops = parse_received_chain(header_block)
    public_ips = [ip for ip in IP_RE.findall(header_block) if not PRIVATE_IP_RE.match(ip)]
    ip_literal_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip_literal_link) if ip_literal_link else None
    target_ip = ip_literal_match.group(0) if ip_literal_match else (public_ips[0] if public_ips else None)

    return {
        "subject": subject,
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "auth_results": auth_results,
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "score": score,
        "indicators": indicators,
        "relay_hops": relay_hops,
        "target_ip": target_ip,
    }
