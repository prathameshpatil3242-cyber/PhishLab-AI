"""
tests/test_analyzer.py
----------------------
Tests for the rule-based message analyzer and the static URL analyzer.

Everything here works on plain text — no network access, no URL opening,
no message delivery.
"""

import pytest

from phishlab import analyzer, url_analyzer

# ---------------------------------------------------------------------------
# Message analysis — ordinary fictional messages
# ---------------------------------------------------------------------------

ORDINARY_MESSAGES = [
    (
        "From: lab-coordinator@tkiet.example.edu\n"
        "Subject: Cyber Security lab batch — room change\n\n"
        "Hello everyone, tomorrow's lab will run in Room 204. Please bring your "
        "laptops and the printed worksheet. Regards, Lab Coordinator"
    ),
    (
        "Hi Team, the workshop slides are attached to the college portal. "
        "Feel free to ask doubts in tomorrow's session."
    ),
    (
        "From: library@example.test\nSubject: Book return reminder\n\n"
        "The borrowed book is due on Friday. You can renew it from the library "
        "counter during working hours."
    ),
]


@pytest.mark.parametrize("message", ORDINARY_MESSAGES)
def test_ordinary_message_has_no_strong_flags(message):
    result = analyzer.analyze_message(message)
    assert result["classification"] == "No obvious indicators"
    assert result["risk_score"] < 25
    assert result["risk_level"] == "Low"
    assert isinstance(result["indicators"], list)
    assert isinstance(result["recommendations"], list)
    assert result["recommendations"], "some safety advice must always be shown"


# ---------------------------------------------------------------------------
# Message analysis — fictional suspicious messages
# ---------------------------------------------------------------------------

SUSPICIOUS_MESSAGES = [
    (
        "From: security@paypa1-verify.com\n"
        "Subject: Urgent: your account will be suspended\n\n"
        "Dear customer, verify your password within 24 hours or your account "
        "will be closed. Click here to verify now: http://192.168.10.44/verify\n"
        "Failure to respond will lead to permanent suspension."
    ),
    (
        "Congratulations! You have won a free gift card. Claim your prize now by "
        "confirming your bank account number and paying the small processing fee. "
        "Do not tell anyone about this offer."
    ),
    (
        "Your mailbox is full. Sign in at https://secure-login.example-verify.xyz/mail "
        "to confirm your password and restore access immediately. This is time sensitive."
    ),
]


@pytest.mark.parametrize("message", SUSPICIOUS_MESSAGES)
def test_suspicious_message_is_flagged(message):
    result = analyzer.analyze_message(message)
    assert result["classification"] in ("Potential phishing", "Needs review")
    assert result["risk_score"] >= 25
    assert len(result["indicators"]) >= 2
    evidence = " ".join(i["evidence"] for i in result["indicators"])
    assert evidence.strip(), "every indicator must show its evidence"


def test_credential_request_is_detected():
    result = analyzer.analyze_message(
        "Dear customer, please reply with your password and one-time code."
    )
    ids = {i["id"] for i in result["indicators"]}
    assert "credential" in ids


def test_urgency_alone_does_not_mean_phishing():
    """Urgent wording by itself must not be called 'Potential phishing'."""
    result = analyzer.analyze_message(
        "Please submit the lab record immediately before the deadline."
    )
    assert result["classification"] != "Potential phishing"
    assert result["risk_score"] < 55


def test_explanation_and_disclaimer_are_present():
    result = analyzer.analyze_message(
        "Dear customer, verify your password within 24 hours."
    )
    assert "score" in result["score_explanation"].lower()
    assert "not a guaranteed verdict" in result["summary"].lower()
    assert "wrong" in result["disclaimer"].lower()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_empty_message_is_rejected():
    with pytest.raises(ValueError):
        analyzer.analyze_message("")
    with pytest.raises(ValueError):
        analyzer.analyze_message("     ")
    with pytest.raises(ValueError):
        analyzer.analyze_message(None)


def test_very_long_message_is_rejected():
    with pytest.raises(ValueError):
        analyzer.analyze_message("x" * 60_001)


def test_very_long_but_accepted_message():
    """Just under the limit must still work (documents the boundary)."""
    message = "Please submit the report. " * 2000        # ~52,000 chars
    assert len(message) < 60_000
    result = analyzer.analyze_message(message)
    assert result["risk_score"] >= 0


# ---------------------------------------------------------------------------
# URL analysis (text only — never visited)
# ---------------------------------------------------------------------------

def test_url_with_ip_host_is_flagged_but_not_fatal():
    result = url_analyzer.analyze_url("http://192.168.10.44/verify/account/login")
    names = [c["name"] for c in result["checks"]]
    assert "Hostname is an IP address" in names
    assert result["risk_score"] >= 25
    assert "did NOT visit" in result["summary"]


def test_ordinary_url_has_few_indicators():
    result = url_analyzer.analyze_url("https://tkiet.example.edu/notice")
    assert result["risk_score"] < 25
    assert result["classification"] == "Few static indicators found"


def test_https_alone_is_never_called_proof_of_safety():
    result = url_analyzer.analyze_url("https://example.org/login")
    scheme_check = next(c for c in result["checks"] if c["name"] == "URL scheme")
    assert "NOT prove" in scheme_check["why"] or "does NOT" in scheme_check["why"]


def test_lookalike_domain_is_flagged():
    result = url_analyzer.analyze_url("https://secure-paypal.login.verify-account.top/session")
    assert result["risk_score"] >= 25
    assert any(c["status"] == "risk" for c in result["checks"])


@pytest.mark.parametrize("bad_url", ["", "   ", "x" * 2100])
def test_malformed_urls_are_rejected(bad_url):
    with pytest.raises(ValueError):
        url_analyzer.analyze_url(bad_url)


def test_url_with_control_characters_is_rejected():
    with pytest.raises(ValueError):
        url_analyzer.analyze_url("http://example.org/\nSet-Cookie: evil=1")


def test_url_score_never_exceeds_100():
    result = url_analyzer.analyze_url(
        "http://user:pass@192.168.1.9:8080/a/b/c/login/verify.html.exe?x=1&y=2&z=3"
    )
    assert 0 <= result["risk_score"] <= 100


# ---------------------------------------------------------------------------
# Missing model handling (phishlab.train_model)
# ---------------------------------------------------------------------------

def test_missing_model_returns_helpful_error(tmp_path):
    from phishlab import train_model

    pipeline, error = train_model.load_model(str(tmp_path / "does-not-exist.joblib"))
    assert pipeline is None
    assert error and "model" in error.lower()


def test_prediction_without_model_raises_train_error(tmp_path):
    from phishlab import train_model

    with pytest.raises(train_model.TrainError):
        train_model.predict(None, "some text")


def test_status_reports_untrained_model(tmp_path):
    from phishlab import train_model

    status = train_model.status(str(tmp_path / "metrics.json"),
                                str(tmp_path / "model.joblib"))
    assert status["trained"] is False
    assert status["model_exists"] is False
    assert status["metrics"] is None
