"""
phishlab/analyzer.py
--------------------
Rule-based (non machine-learning) analysis of message text.

WHY RULES?
    Rules are transparent.  Every warning shown to the user is tied to a
    named rule and a piece of evidence found inside the message, so the
    student can explain *why* the message was flagged.

IMPORTANT SAFETY NOTES
    * The analyzer only reads the text you paste in.  It never opens links,
      never downloads attachments and never contacts external services.
    * The result is a *prediction*, not a verified fact.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Small helper patterns
# ---------------------------------------------------------------------------

# Finds e-mail addresses such as "support@paypa1-security.com"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Finds web addresses inside the text (http/https or www.)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

# Fictional/real brand names that attackers commonly imitate.
BRAND_NAMES = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "hdfc", "sbi", "icici",
    "instagram", "linkedin", "coinbase", "binance", "olx", "flipkart",
    "instagram", "govt", "income tax", "aadhaar",
]

# Common URL shorteners (they hide the real destination)
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at",
]


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule has:
#   id          -> short identifier shown in the results
#   name        -> human readable title
#   description -> what this rule means and why it matters
#   weight      -> how many risk points the rule adds (0-100 scale total)
#   check(text, info) -> returns (matched: bool, evidence: str)
# ---------------------------------------------------------------------------

def _match_keywords(text, keywords):
    """Return the first keyword found inside text (case-insensitive)."""
    low = text.lower()
    for kw in keywords:
        if kw in low:
            return kw
    return None


def _rule_urgency(text, info):
    kw = _match_keywords(text, [
        "immediately", "urgent", "within 24 hours", "act now",
        "suspend your account", "account will be closed", "final warning",
        "unauthorized activity", "expires today", "last chance",
        "failure to respond", "legal action", "your account will be locked",
        "as soon as possible", "time sensitive",
    ])
    if kw:
        return True, f'Urgency/threat phrase found: "{kw}"'
    return False, ""


def _rule_credential_request(text, info):
    kw = _match_keywords(text, [
        "your password", "verify your password", "confirm your password",
        "one-time code", "otp", "verification code", "credit card number",
        "card number", "cvv", "social security", "bank account number",
        "share your password", "enter your login", "ssn", "pin number",
        "mother's maiden name", "date of birth",
    ])
    if kw:
        return True, f'Request for sensitive data: "{kw}"'
    return False, ""


def _rule_verification_request(text, info):
    kw = _match_keywords(text, [
        "verify your account", "confirm your identity", "validate your account",
        "update your information", "re-verify", "verify your identity",
        "click here to verify", "confirm your details", "verify now",
        "security check", "account verification",
    ])
    if kw:
        return True, f'Account verification request: "{kw}"'
    return False, ""


def _rule_generic_greeting(text, info):
    kw = _match_keywords(text, [
        "dear customer", "dear user", "dear member", "dear account holder",
        "dear sir", "dear user", "to whom it may concern", "dear valued customer",
    ])
    if kw:
        return True, f'Generic greeting instead of your real name: "{kw}"'
    return False, ""


# Common "leetspeak" substitutions used to hide a brand name (paypa1 -> paypal)
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                       "7": "t", "@": "a", "$": "s", "!": "i"})


def _rule_sender_irregularity(text, info):
    """Check the 'From:' style sender line if the user supplied one."""
    sender_block = info.get("sender_block", "")
    if not sender_block:
        return False, ""

    emails = EMAIL_RE.findall(sender_block)
    if not emails:
        return True, "A sender line was supplied but contains no valid e-mail address."

    address = emails[0]
    domain = address.split("@")[1].lower()
    local = address.split("@")[0].lower()
    whole = f"{local}{domain}"
    whole_leet = whole.translate(_LEET)

    # 1) Lookalike spelling: brand only appears AFTER undoing digit tricks
    for brand in BRAND_NAMES:
        core = brand.split()[0]
        if len(core) < 4:
            continue
        if core not in whole and core in whole_leet:
            return True, f'Sender address "{address}" is a lookalike spelling of "{brand.strip()}".'

    # 2) Display name says one company, but the real domain is different
    display_match = re.search(
        r"^([^<@]{2,60})<\s*" + re.escape(address),
        sender_block, re.IGNORECASE | re.MULTILINE,
    )
    if display_match:
        display = display_match.group(1).lower()
        for brand in BRAND_NAMES:
            core = brand.split()[0]
            if len(core) >= 4 and core in display and core not in domain:
                return True, (
                    f'Display name mentions "{brand.strip()}" but the real domain is '
                    f'"{domain}" (name and address do not match).'
                )

    # 3) Unusual domain shape: many hyphens or a long run of digits
    if domain.count("-") >= 3:
        return True, f'Sender domain "{domain}" contains an unusual number of hyphens.'
    if re.search(r"\d{3,}", domain):
        return True, f'Sender domain "{domain}" contains a long run of digits.'

    return False, ""


def _rule_suspicious_links(text, info):
    urls = info.get("urls", [])
    if not urls:
        return False, ""

    for u in urls:
        low = u.lower()
        # Raw IP address host
        host = ""
        try:
            host = (urlparse(u if "://" in u else "http://" + u).hostname or "")
        except Exception:
            host = ""
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
            return True, f"Link points directly at an IP address instead of a website name: {u}"

        for s in SHORTENERS:
            if s in low:
                return True, f'Link uses the shortener "{s}" which hides the real destination.'

        # Mismatched link text (text says paypal.com but link goes elsewhere)
        link_text_match = re.search(
            r"(?P<label>[\w.\-]+\.(?:com|net|org|in|co|io|info|biz|xyz))\s*(?:->|→)\s*(?P<link>https?://\S+)",
            text, re.IGNORECASE,
        )
        if link_text_match:
            label = link_text_match.group("label").lower().split(".")[-2]
            link = link_text_match.group("link").lower()
            if label and label not in link:
                return True, (
                    f'Mismatched link: text shows "{link_text_match.group("label")}" '
                    f'but the real link is {link_text_match.group("link")}'
                )

    return True, f"{len(urls)} link(s) present in the message — always hover and check the full address before clicking."


def _rule_secretive_language(text, info):
    kw = _match_keywords(text, [
        "do not tell anyone", "keep this confidential", "do not inform",
        "this is a secret", "between you and me", "do not share with",
        "for your eyes only",
    ])
    if kw:
        return True, f'Secrecy pressure: "{kw}"'
    return False, ""


def _rule_prize_reward(text, info):
    kw = _match_keywords(text, [
        "you have won", "you won", "congratulations", "free gift",
        "lottery", "jackpot", "claim your prize", "reward",
        "you are selected", "winner", "cash prize",
    ])
    if kw:
        return True, f'Reward/prize bait: "{kw}"'
    return False, ""


def _rule_attachment(text, info):
    kw = _match_keywords(text, [
        "open the attached", "attachment", "attached invoice",
        ".exe", ".scr", "enable macros", "password protected file",
        "zip file", "download the invoice",
    ])
    if kw:
        return True, f'Attachment-related instruction: "{kw}"'
    return False, ""


def _rule_poor_grammar(text, info):
    # Cheap but explainable signals: odd capitalisation / missing spaces / excessive !
    evidence = []
    if re.search(r"[A-Z]{4,}", text):
        evidence.append("words typed in FULL CAPS")
    if text.count("!") >= 3:
        evidence.append("three or more exclamation marks")
    if re.search(r"\s{2,}[a-z]", text) and text.count("  ") >= 3:
        evidence.append("repeated double spaces (possible template merge error)")
    if re.search(r"\b(dear|hi)\s+(customer|user),?\s+", text, re.I) and "!" in text:
        evidence.append("formal greeting combined with excited punctuation")
    if evidence:
        return True, "Writing quality signals: " + ", ".join(evidence)
    return False, ""


def _rule_money_request(text, info):
    kw = _match_keywords(text, [
        "transfer money", "wire transfer", "pay immediately", "gift card",
        "bitcoin", "crypto wallet", "western union", "pay the fee",
        "processing fee", "tax fee", "release fee", "refund pending",
        "bank transfer", "upi id", "send the payment",
    ])
    if kw:
        return True, f'Money/payment request: "{kw}"'
    return False, ""


def _rule_impersonation(text, info):
    """Mentions of a well-known organisation combined with an action request."""
    brand = _match_keywords(text, BRAND_NAMES)
    if not brand:
        return False, ""
    if _match_keywords(text, ["click", "verify", "confirm", "update", "login", "sign in", "reply", "download"]):
        return True, f'Message impersonates "{brand.strip()}" and asks you to take an action.'
    return False, ""


def _rule_reply_to(text, info):
    block = info.get("sender_block", "").lower()
    if "reply-to" in block or "reply to" in block:
        emails = EMAIL_RE.findall(info.get("sender_block", ""))
        if len(emails) >= 2:
            return True, "Reply-To address differs from the From address (replies would go elsewhere)."
    return False, ""


def _rule_https_not_proof(text, info):
    """People often think https = safe.  Point out when links are http:// only."""
    urls = info.get("urls", [])
    plain = [u for u in urls if u.lower().startswith("http://")]
    if plain:
        return True, f'{len(plain)} plain HTTP link(s) without encryption: {plain[0]}'
    return False, ""


RULES = [
    {"id": "urgency",       "name": "Urgent or threatening language",     "weight": 15,
     "description": "Attackers create panic so you act before thinking. Deadlines, threats of closure or legal action are classic pressure tactics.",
     "check": _rule_urgency},
    {"id": "credential",    "name": "Request for passwords or sensitive data", "weight": 22,
     "description": "Legitimate organisations never ask you to send passwords, OTPs, card numbers or IDs by message.",
     "check": _rule_credential_request},
    {"id": "verification",  "name": "Account verification request",        "weight": 14,
     "description": "\"Verify your account\" links are a common way to steer victims to a fake login page.",
     "check": _rule_verification_request},
    {"id": "sender",        "name": "Unusual sender information",          "weight": 16,
     "description": "Misspelled domains, display-name/domain mismatch and digit tricks imitate real brands.",
     "check": _rule_sender_irregularity},
    {"id": "links",         "name": "Suspicious or hidden links",          "weight": 14,
     "description": "IP-based links, URL shorteners and mismatched link text hide the real destination.",
     "check": _rule_suspicious_links},
    {"id": "impersonation", "name": "Impersonation of a known organisation", "weight": 10,
     "description": "Mentioning a famous brand plus an action request is how phishing messages borrow trust.",
     "check": _rule_impersonation},
    {"id": "greeting",      "name": "Generic greeting",                    "weight": 6,
     "description": "\"Dear customer\" suggests a mass mailing rather than a message meant for you.",
     "check": _rule_generic_greeting},
    {"id": "reward",        "name": "Prize / reward bait",                 "weight": 10,
     "description": "Too-good-to-be-true rewards push people to click without checking.",
     "check": _rule_prize_reward},
    {"id": "money",         "name": "Money or payment request",            "weight": 18,
     "description": "Requests to transfer money, pay fees or buy gift cards are strong phishing signals.",
     "check": _rule_money_request},
    {"id": "secret",        "name": "Secrecy pressure",                    "weight": 8,
     "description": "\"Don't tell anyone\" stops victims from verifying with a trusted person.",
     "check": _rule_secretive_language},
    {"id": "attachment",    "name": "Suspicious attachment instruction",   "weight": 12,
     "description": "Attachments and macro-enabled files are a common malware delivery method.",
     "check": _rule_attachment},
    {"id": "grammar",       "name": "Unusual writing style",               "weight": 6,
     "description": "ALL CAPS, excessive punctuation and template errors often appear in bulk-crafted messages.",
     "check": _rule_poor_grammar},
    {"id": "replyto",       "name": "Mismatched reply address",            "weight": 12,
     "description": "A Reply-To different from From redirects your answer to the attacker.",
     "check": _rule_reply_to},
    {"id": "plaintext",     "name": "Unencrypted HTTP link",               "weight": 8,
     "description": "http:// links can be intercepted or modified in transit. HTTPS is necessary but never proof of safety.",
     "check": _rule_https_not_proof},
]


# ---------------------------------------------------------------------------
# Pre-processing helpers
# ---------------------------------------------------------------------------

def _extract_sender_block(text):
    """
    If the pasted text starts with header-style lines (From:, To:, Subject:),
    capture the part before the first empty line so sender rules can work.
    """
    lines = text.splitlines()
    header_lines = []
    for line in lines:
        if not line.strip():
            break
        if re.match(r"^\s*(from|to|subject|reply-to|date|message-id|return-path)\s*:", line, re.I):
            header_lines.append(line)
        elif header_lines:
            header_lines.append(line)   # continuation of a header
        elif len(header_lines) == 0 and len(line) > 200:
            break
    return "\n".join(header_lines)


def analyze_message(text, source="live"):
    """
    Analyse a message and return an explainable result dictionary.

    Parameters
    ----------
    text : str   The message text supplied by the user.
    source : str 'live' for real user input, 'demo' for seeded records.

    Returns
    -------
    dict with keys:
        classification   -> "Potential phishing" | "Needs review" | "No obvious indicators"
        risk_score       -> 0..100 integer
        risk_level       -> Low | Medium | High | Critical
        score_explanation-> how the score was calculated (string)
        indicators       -> list of dicts {id, name, description, weight, evidence}
        recommendations  -> list of strings
        disclaimer       -> reminder that this is a prediction
        summary          -> one-paragraph human readable summary
    """
    if text is None:
        text = ""
    text = str(text).strip()

    if not text:
        raise ValueError("Please paste a message before analysing.")

    if len(text) > 60_000:
        raise ValueError("Message is too long (maximum 60,000 characters).")

    info = {
        "urls": URL_RE.findall(text),
        "emails": EMAIL_RE.findall(text),
        "sender_block": _extract_sender_block(text),
    }

    indicators = []
    raw_score = 0

    for rule in RULES:
        try:
            matched, evidence = rule["check"](text, info)
        except Exception as exc:            # never let one rule break the page
            matched, evidence = False, f"(rule error: {exc})"
        if matched:
            raw_score += rule["weight"]
            indicators.append({
                "id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "weight": rule["weight"],
                "evidence": evidence,
            })

    risk_score = min(100, raw_score)

    # --- Classification thresholds -------------------------------------
    if risk_score >= 55:
        classification = "Potential phishing"
    elif risk_score >= 25:
        classification = "Needs review"
    else:
        classification = "No obvious indicators"

    if risk_score >= 75:
        risk_level = "Critical"
    elif risk_score >= 55:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    matched_weight = sum(i["weight"] for i in indicators)
    capped = matched_weight == risk_score
    score_explanation = (
        f"Each warning sign has a fixed weight that reflects how strongly it is "
        f"associated with phishing messages in teaching material. "
        f"Matched weights: {' + '.join(str(i['weight']) for i in indicators) or '0'} "
        f"= {matched_weight}. "
        + (f"The total was capped at the maximum of 100." if not capped else
           "The score stays within the 0-100 scale.")
        + f" Score {risk_score}/100 → {classification} ({risk_level} risk)."
    )

    recommendations = build_recommendations(indicators, classification)

    summary = (
        f"The rule engine checked {len(RULES)} explainable indicators and "
        f"matched {len(indicators)}. "
        f"Result: {classification} with a risk indicator of {risk_score}/100. "
        f"This is an educational prediction, not a guaranteed verdict."
    )

    return {
        "classification": classification,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "score_explanation": score_explanation,
        "indicators": indicators,
        "checked_rules": len(RULES),
        "recommendations": recommendations,
        "disclaimer": (
            "This result is generated by a simple rule engine and/or a demonstration "
            "machine-learning model. Predictions can be wrong. Always verify the "
            "message with the official app or website of the organisation mentioned."
        ),
        "summary": summary,
        "source": source,
        "detected_urls": info["urls"][:10],
        "detected_emails": info["emails"][:10],
    }


def build_recommendations(indicators, classification):
    """Return practical, safe advice based on which rules matched."""
    ids = {i["id"] for i in indicators}
    recs = []

    if "credential" in ids or "verification" in ids:
        recs.append("Do not enter your password, OTP or card details from a link in this message. Open the official app/website yourself instead.")
    if "links" in ids or "plaintext" in ids:
        recs.append("Hover over every link and read the full address carefully. Prefer typing the website address manually.")
    if "sender" in ids or "replyto" in ids:
        recs.append("Verify the sender through a separate channel (official website, phone number on your card, or the organisation's app).")
    if "urgency" in ids or "secret" in ids:
        recs.append("Slow down. Urgent threats are designed to stop you thinking — take a few minutes and check independently.")
    if "money" in ids:
        recs.append("Never transfer money or buy gift cards because of an unsolicited message. Report it to the real organisation.")
    if "attachment" in ids:
        recs.append("Do not open unexpected attachments. If the message claims to be from someone you know, confirm with them first.")
    if "impersonation" in ids:
        recs.append("Contact the organisation using the number or website you already trust, not any link in the message.")

    if classification == "Potential phishing":
        recs.insert(0, "Treat this message as suspicious: do not click links, download files or reply with personal information.")
    elif classification == "Needs review":
        recs.insert(0, "Pause and verify this message independently before taking any action.")
    else:
        recs.insert(0, "No strong warning signs were found, but stay careful — a clean result never guarantees a message is safe.")

    # Always useful advice
    recs.append("Report phishing attempts to the real organisation and to your national cybercrime portal.")
    recs.append("Enable two-factor authentication on important accounts to limit damage if a password ever leaks.")
    return recs
