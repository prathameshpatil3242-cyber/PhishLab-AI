"""
phishlab/url_analyzer.py
------------------------
STATIC analysis of a URL string.

HARD SAFETY RULES (built into this module)
    * The submitted URL is NEVER visited, fetched, resolved or downloaded.
    * No file is opened and no content is executed.
    * HTTPS alone is NEVER treated as proof that a URL is safe.
    * Output is a *preliminary assessment*, not a verdict.

Everything here works on the text of the URL using Python's urllib.parse.
"""

import ipaddress
import re
from urllib.parse import urlparse, unquote

# --- Static lists (teaching material, not live threat intelligence) --------

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "lnkd.in", "s.id", "v.gd",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work",
    "click", "link", "loan", "country", "stream", "download", "racing",
}

# Frequently imitated brands (used to spot misleading domain strings)
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "binance",
    "coinbase", "flipkart", "olx", "hdfc", "sbi", "icici",
]

# Words that often appear in fake login / verification pages
SENSITIVE_PATH_WORDS = [
    "login", "signin", "sign-in", "logon", "verify", "verification",
    "secure", "account", "update", "confirm", "password", "wallet",
    "bank", "auth", "sso", "session", "unlock", "recover", "invoice",
]

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                       "7": "t", "@": "a", "$": "s"})


def _check(name, status, detail, weight, why):
    """Helper that builds one result row in a consistent format."""
    return {"name": name, "status": status, "detail": detail,
            "weight": weight, "why": why}


def analyze_url(url, source="live"):
    """
    Analyse the *text* of a URL and return an explainable result.

    status values:  ok  |  warn  |  risk

    Returns a dict with:
        url, parsed, checks, risk_score, risk_level, classification,
        score_explanation, recommendations, disclaimer, summary, source
    """
    if url is None:
        raise ValueError("Please enter a URL to analyse.")
    url = str(url).strip()

    if not url:
        raise ValueError("Please enter a URL to analyse.")
    if len(url) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    if any(ch in url for ch in ("\n", "\r", "\x00")):
        raise ValueError("URL contains invalid control characters.")

    # Add a scheme so urlparse can split the parts, but remember whether
    # the user typed one.
    had_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url)) or url.startswith("//")
    working = url
    if working.startswith("//"):
        working = "http:" + working
    elif not had_scheme:
        working = "http://" + working      # parse only — never contacted

    try:
        parsed = urlparse(working)
        hostname = parsed.hostname or ""
    except Exception as exc:
        raise ValueError(f"Could not parse this URL: {exc}")

    checks = []

    # ------------------------------------------------------------------
    # 1) Scheme: HTTPS / HTTP / other / missing
    # ------------------------------------------------------------------
    scheme = (parsed.scheme or "").lower()
    if not had_scheme:
        checks.append(_check(
            "URL scheme", "warn", "No scheme was typed, so http:// was assumed for parsing only.",
            8, "Users should see https:// in front of a real address. A missing scheme is easy to miss visually."))
    elif scheme == "https":
        checks.append(_check(
            "URL scheme", "ok", "Uses https:// (encrypted transport).",
            0, "HTTPS protects data in transit, but it does NOT prove the website is legitimate — phishing sites also use HTTPS."))
    elif scheme == "http":
        checks.append(_check(
            "URL scheme", "warn", "Uses plain http:// (no encryption).",
            10, "Traffic can be read or modified on the network. Combined with a login page this is dangerous."))
    elif scheme in ("ftp", "file", "data", "javascript", "gopher", "ws", "wss"):
        checks.append(_check(
            "URL scheme", "risk", f"Unusual scheme '{scheme}://'.",
            20, "Everyday web links use http/https. Other schemes can trigger unexpected behaviour."))
    else:
        checks.append(_check(
            "URL scheme", "warn", f"Unrecognised scheme '{scheme}://'.",
            12, "Unexpected schemes are rare in normal links."))

    # ------------------------------------------------------------------
    # 2) Hostname checks
    # ------------------------------------------------------------------
    # a) IP address used as the hostname
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        checks.append(_check(
            "Hostname is an IP address", "risk", f"Host is {hostname}.",
            20, "Real services use domain names. A raw IP hides the identity of the site owner."))
    else:
        checks.append(_check(
            "Hostname is an IP address", "ok", "A domain name is used, not a raw IP address.",
            0, "Domain names are easier to verify than bare IP addresses."))

    # b) localhost / private-range style names
    low_host = hostname.lower()
    if low_host in ("localhost", "127.0.0.1", "0.0.0.0") or low_host.endswith(".local"):
        checks.append(_check(
            "Local/private host", "warn", f"'{hostname}' points at a local machine.",
            10, "Local addresses in a shared link are unusual and may be used to confuse tools."))

    # c) excessive subdomains
    host_parts = low_host.split(".") if low_host else []
    subdomain_count = max(0, len(host_parts) - 2)
    if subdomain_count >= 4:
        checks.append(_check(
            "Unusual subdomain depth", "risk", f"{subdomain_count} subdomains before the main domain.",
            14, "Deep nesting such as a.b.c.d.example.com hides the real registered domain from a quick glance."))
    elif subdomain_count >= 2:
        checks.append(_check(
            "Subdomain count", "warn", f"{subdomain_count} subdomain(s) present.",
            6, "Many subdomains are common for big sites, but combined with other warnings it deserves a second look."))
    else:
        checks.append(_check(
            "Subdomain count", "ok", "Normal subdomain structure.",
            0, "A short hostname is easier for a person to verify."))

    # d) lookalike / misleading domain string
    lookalike_hits = []
    for brand in IMPERSONATED_BRANDS:
        raw = f"{hostname}"
        leet = raw.translate(_LEET)
        if brand in raw:
            # Brand appears — check it is in the *registered* domain,
            # not merely in a subdomain (secure.paypal.evil.com).
            registered = ".".join(host_parts[-3:]) if len(host_parts) >= 3 else raw
            if brand not in ".".join(host_parts[-2:]) and len(host_parts) > 2:
                lookalike_hits.append(f'"{brand}" only appears inside a subdomain of {hostname}')
            elif brand in raw and brand not in ".".join(host_parts[-2:]):
                lookalike_hits.append(f'"{brand}" appears in "{hostname}" but not in the main domain')
        elif brand in leet and brand not in raw:
            lookalike_hits.append(f'"{hostname}" is a digit lookalike of "{brand}"')
    # hyphen/digit tricks like "paypal-secure-login.com"
    if re.search(r"(paypal|amazon|google|microsoft|apple|instagram|facebook)", hostname) and \
       re.search(r"[-.](secure|login|verify|account|update|support|auth|client|portal|billing)[-.]", hostname):
        lookalike_hits.append("The domain mixes a famous brand with words like 'secure/login/verify'.")

    if lookalike_hits:
        checks.append(_check(
            "Misleading domain string", "risk", "; ".join(sorted(set(lookalike_hits))[:3]),
            18, "Attackers build domains that *look* like a brand at a glance but are registered elsewhere."))
    else:
        checks.append(_check(
            "Misleading domain string", "ok", "No obvious brand-lookalike pattern detected.",
            0, "Absence of a pattern does not prove legitimacy."))

    # e) hyphens / digits / length of hostname
    hyphens = hostname.count("-")
    if hyphens >= 3:
        checks.append(_check(
            "Hyphen-heavy hostname", "warn", f"{hyphens} hyphens in the hostname.",
            8, "Names like pay-secure-login-verify.com are common in generated phishing domains."))
    if re.search(r"\d{3,}", hostname):
        checks.append(_check(
            "Long digit run in hostname", "warn", "Hostname contains 3+ digits in a row.",
            6, "Random digit runs often indicate an automatically generated domain."))

    # f) punycode (internationalised domain that can spoof characters)
    if "xn--" in hostname:
        checks.append(_check(
            "Punycode / international domain", "risk", "Hostname contains 'xn--' (encoded foreign characters).",
            14, "Punycode can visually imitate another domain using different alphabets."))

    # ------------------------------------------------------------------
    # 3) Whole-URL checks
    # ------------------------------------------------------------------
    # a) length
    if len(url) > 150:
        checks.append(_check(
            "Very long URL", "risk", f"{len(url)} characters long.",
            12, "Extreme length hides the real destination and often packs many tracking/redirect parameters."))
    elif len(url) > 75:
        checks.append(_check(
            "Long URL", "warn", f"{len(url)} characters long.",
            6, "Long URLs are harder for humans to check — read the hostname part carefully."))
    else:
        checks.append(_check(
            "URL length", "ok", f"{len(url)} characters (reasonable).",
            0, "Shorter URLs are easier to verify visually."))

    # b) embedded credentials (http://paypal.com@evil.com)
    if "@" in (parsed.netloc or ""):
        checks.append(_check(
            " '@' inside the URL", "risk", "The URL contains '@' before the path.",
            18, "Everything before '@' is user info; the part after '@' is the real host — a classic trick."))

    # c) URL shortener
    short_hit = next((s for s in SHORTENER_DOMAINS if low_host == s or low_host.endswith("." + s)), None)
    if short_hit:
        checks.append(_check(
            "URL shortener", "risk", f"Uses the shortener '{short_hit}'.",
            16, "Shorteners hide the final destination and cannot be checked without resolving the link (which this tool never does)."))

    # d) non-standard port
    if parsed.port and parsed.port not in (80, 443):
        checks.append(_check(
            "Non-standard port", "warn", f"Port {parsed.port} is used.",
            8, "Everyday sites use 80/443. Odd ports often mean a hobby or attacker-controlled server."))

    # e) sensitive words in path/query
    path_and_query = unquote(f"{parsed.path}?{parsed.query}").lower()
    sensitive_hits = [w for w in SENSITIVE_PATH_WORDS if w in path_and_query]
    if sensitive_hits:
        checks.append(_check(
            "Sensitive words in the path", "warn",
            "Words found: " + ", ".join(sorted(set(sensitive_hits))[:6]),
            10, "Fake login pages usually live at paths like /login, /verify, /update."))

    # f) double extension in the path (invoice.pdf.exe)
    if re.search(r"\.(pdf|doc|docx|jpg|png|html|zip)\.(exe|scr|js|bat|cmd|jar|vbs)\b", path_and_query, re.I):
        checks.append(_check(
            "Double file extension", "risk", "Path ends with a hidden executable extension.",
            20, "A file that looks like a document but is really a program is a classic malware trick."))

    # g) excessive query parameters / encoded separators
    query_params = [p for p in parsed.query.split("&") if p]
    if len(query_params) >= 6:
        checks.append(_check(
            "Many query parameters", "warn", f"{len(query_params)} parameters in the query string.",
            6, "Parameter stuffing can hide the real destination behind long tracking strings."))
    if "%2f%2f" in url.lower() or "%40%40" in url.lower():
        checks.append(_check(
            "Heavy URL encoding", "warn", "Doubly encoded separators found.",
            8, "Encoding layers are used to make the link unreadable to humans."))

    # h) IP literal anywhere in the URL
    ip_in_url = re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url)
    if ip_in_url and not is_ip:
        checks.append(_check(
            "Embedded IP address", "warn", f"URL contains an IP: {ip_in_url.group(0)}",
            10, "Legitimate services normally use their own domain name."))

    # ------------------------------------------------------------------
    # Score
    # ------------------------------------------------------------------
    raw = sum(c["weight"] for c in checks if c["status"] != "ok")
    risk_score = min(100, raw)

    if risk_score >= 55:
        classification = "Elevated indicators — do not trust blindly"
    elif risk_score >= 25:
        classification = "Some indicators — verify before use"
    else:
        classification = "Few static indicators found"

    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 55:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    weights = [str(c["weight"]) for c in checks if c["weight"]]
    score_explanation = (
        "Every check has a fixed teaching weight. Weights of the checks that "
        "did not pass: " + (" + ".join(weights) if weights else "none") +
        f" = {raw}. The total is capped at 100. "
        f"Score {risk_score}/100 → {classification} ({risk_level} risk)."
    )

    recommendations = [
        "Type important website addresses yourself, or use a bookmark you created earlier.",
        "Check the registered domain (the part just before the first single slash) — that identifies the real owner.",
        "Remember: a padlock/HTTPS only means the connection is encrypted, not that the site is honest.",
        "If the message came with this link, verify it through the official app or a known phone number.",
        "Use a password manager — it will refuse to fill credentials on a look-alike domain.",
    ]
    if risk_score >= 55:
        recommendations.insert(0, "Treat this URL as suspicious: do not open it on this or any device.")

    warns = sum(1 for c in checks if c["status"] == "warn")
    risks = sum(1 for c in checks if c["status"] == "risk")
    summary = (
        f"{len(checks)} static checks performed: {risks} warning(s) at risk level, "
        f"{warns} at caution level. Preliminary score {risk_score}/100 ({risk_level} risk). "
        f"This tool did NOT visit the URL."
    )

    return {
        "url": url,
        "parsed": {
            "scheme": scheme if had_scheme else "(none typed)",
            "hostname": hostname,
            "port": parsed.port,
            "path": parsed.path or "/",
            "query_length": len(parsed.query),
            "subdomain_count": subdomain_count,
            "length": len(url),
        },
        "checks": checks,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "score_explanation": score_explanation,
        "recommendations": recommendations,
        "disclaimer": (
            "PRELIMINARY ASSESSMENT ONLY. This tool reads the URL as plain text. "
            "It does not visit the site, does not download anything and cannot know "
            "what the page really does. A clean result does NOT mean the URL is safe, "
            "and HTTPS alone never proves safety."
        ),
        "summary": summary,
        "source": source,
    }
