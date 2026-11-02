"""
tests/test_routes.py
--------------------
Tests for the Flask pages, forms, JSON APIs and the local database.

Nothing here contacts the network: the test client talks to an in-process
Flask application and the database is a temporary SQLite file.
"""

import json
import os

import pytest

import config
from phishlab import storage, train_model

PHISH_MESSAGE = (
    "From: security@paypa1-verify.com\n"
    "Subject: Urgent: your account will be suspended\n\n"
    "Dear customer, verify your password within 24 hours or your account will "
    "be closed. Click here to verify now: http://192.168.10.44/verify"
)

ORDINARY_MESSAGE = (
    "Hello team, tomorrow's Cyber Security lab is at 10 am in Room 204. "
    "Please bring your laptops. Regards, Lab Coordinator"
)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/analyze", "/url", "/campaigns",
                                  "/quiz", "/learning", "/history", "/about",
                                  "/pricing"])
def test_pages_return_200(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert b"PHISHLAB" in response.data


def test_dashboard_requires_login(client):
    """"/" is gated: anonymous visitors are sent to the login page."""
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_dashboard_visible_when_logged_in(client, login):
    body = client.get("/").data.decode("utf-8", "replace")
    assert "Total messages analyzed" in body


def test_dashboard_shows_kpi_labels(client, login):
    body = client.get("/").data.decode("utf-8", "replace")
    assert "Total messages analyzed" in body
    assert "Flagged for review" in body
    assert "Quizzes completed" in body
    assert "Correct quiz answers" in body
    assert "Educational awareness score" in body


def test_dashboard_contains_chart_canvases(client, login):
    body = client.get("/").data.decode("utf-8", "replace")
    assert "indicatorChart" in body
    assert "outcomeChart" in body
    assert "classChart" in body


def test_unknown_page_returns_404(client):
    assert client.get("/definitely-not-a-page").status_code == 404


# ---------------------------------------------------------------------------
# Message analysis routes
# ---------------------------------------------------------------------------

def test_message_analysis_form(client, csrf_token):
    response = client.post("/analyze", data={
        "message": PHISH_MESSAGE, "csrf_token": csrf_token})
    body = response.data.decode("utf-8", "replace")
    assert response.status_code == 200
    assert "Risk indicators" in body
    assert "Recommended safe action" in body
    assert "educational heuristic" in body


def test_ordinary_message_form_result(client, csrf_token):
    response = client.post("/analyze", data={
        "message": ORDINARY_MESSAGE, "csrf_token": csrf_token})
    body = response.data.decode("utf-8", "replace")
    assert "No obvious phishing indicators" in body


def test_empty_message_is_rejected(client, csrf_token):
    response = client.post("/analyze", data={"message": "", "csrf_token": csrf_token})
    body = response.data.decode("utf-8", "replace")
    assert response.status_code == 200
    assert "Please paste some text" in body


def test_too_long_message_is_rejected(client, csrf_token):
    response = client.post("/analyze", data={
        "message": "a" * 25_000, "csrf_token": csrf_token})
    assert response.status_code == 200
    assert "maximum accepted length" in response.data.decode("utf-8", "replace")


def test_api_analyze_returns_html_and_details(client, csrf_token):
    response = client.post("/api/analyze", json={"message": PHISH_MESSAGE},
                           headers={"X-CSRF-Token": csrf_token})
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["ok"] is True
    assert payload["rules"]["risk_score"] >= 25
    assert payload["ml"] is not None and "available" in payload["ml"]
    assert payload["html"]
    assert "Recommended safe action" in payload["html"]


def test_api_analyze_rejects_empty_payload(client, csrf_token):
    response = client.post("/api/analyze", json={"message": "   "},
                           headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 400
    assert response.get_json()["ok"] is False


def test_analysis_is_stored_locally(client, csrf_token, app):
    client.post("/api/analyze", json={"message": ORDINARY_MESSAGE},
                headers={"X-CSRF-Token": csrf_token})
    rows = storage.fetch_analyses(app, limit=10)
    assert any(r["source"] == "live" for r in rows)
    # only a short snippet is stored, never the full message
    assert all(len(r["title"]) <= 80 for r in rows)


# ---------------------------------------------------------------------------
# URL analysis routes
# ---------------------------------------------------------------------------

def test_url_form_analysis(client, csrf_token):
    response = client.post("/url", data={
        "url": "http://192.168.10.44/verify/account/login",
        "csrf_token": csrf_token})
    body = response.data.decode("utf-8", "replace")
    assert response.status_code == 200
    assert "Hostname is an IP address" in body
    assert "never visited" in body.lower() or "did NOT visit" in body


def test_malformed_url_form_is_rejected(client, csrf_token):
    response = client.post("/url", data={"url": "not a url at all",
                                         "csrf_token": csrf_token})
    body = response.data.decode("utf-8", "replace")
    assert response.status_code == 200
    assert "spaces" in body or "not a complete website" in body


def test_api_url_malformed_returns_400(client, csrf_token):
    response = client.post("/api/url", json={"url": "ht!tp:::??"},
                           headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 400
    assert response.get_json()["ok"] is False


def test_api_url_ok(client, csrf_token):
    response = client.post("/api/url", json={"url": "https://example.org/login"},
                           headers={"X-CSRF-Token": csrf_token})
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["result"]["risk_score"] <= 100
    assert "PRELIMINARY ASSESSMENT" in payload["result"]["disclaimer"]


# ---------------------------------------------------------------------------
# Model status / graceful degradation
# ---------------------------------------------------------------------------

def test_model_status_endpoint_works(client):
    payload = client.get("/api/model/status").get_json()
    assert payload["ok"] is True
    assert "trained" in payload["status"]


def test_analysis_works_without_model(app, client, csrf_token, monkeypatch):
    """Point the app at a non-existent model file — analysis must still work."""
    monkeypatch.setitem(app.config, "MODEL_PATH",
                        "/tmp/definitely-missing-phishlab-model.joblib")
    payload = client.post("/api/analyze", json={"message": PHISH_MESSAGE},
                          headers={"X-CSRF-Token": csrf_token}).get_json()
    assert payload["ok"] is True
    assert payload["ml"]["available"] is False
    assert "train" in payload["ml"]["error"].lower()
    assert payload["rules"]["risk_score"] >= 25


def test_train_endpoint_fails_cleanly_with_missing_dataset(app, client,
                                                           csrf_token, monkeypatch):
    monkeypatch.setitem(app.config, "DATASET_PATH", "/tmp/no-such-dataset.csv")
    response = client.post("/api/train", json={}, headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 400
    assert response.get_json()["ok"] is False
    assert "dataset" in response.get_json()["error"].lower()


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------

def test_quiz_page_shows_first_exercise(client):
    body = client.get("/quiz").data.decode("utf-8", "replace")
    assert "Phishing Awareness Quiz" in body
    assert "Is this message" in body or "exercise_id" in body


def test_quiz_submission_records_result(client, csrf_token, app):
    body = client.get("/quiz").data.decode("utf-8", "replace")
    start = body.index('name="exercise_id" value="') + len('name="exercise_id" value="')
    exercise_id = body[start:body.index('"', start)]

    response = client.post("/quiz", data={
        "exercise_id": exercise_id, "answer_index": "0",
        "signs": ["0", "1"], "csrf_token": csrf_token})
    assert response.status_code == 200
    assert b"points" in response.data

    rows = storage.fetch_quiz_results(app, limit=10)
    assert len(rows) == 1
    assert rows[0]["source"] == "live"
    assert rows[0]["exercise_id"] == exercise_id


def test_quiz_rejects_unknown_exercise(client, csrf_token, app):
    response = client.post("/quiz", data={
        "exercise_id": "does-not-exist", "answer_index": "0",
        "csrf_token": csrf_token}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Unknown exercise" in response.data
    assert storage.fetch_quiz_results(app, limit=10) == []


def test_quiz_rejects_bad_answer_index(client, csrf_token, app):
    body = client.get("/quiz").data.decode("utf-8", "replace")
    start = body.index('name="exercise_id" value="') + len('name="exercise_id" value="')
    exercise_id = body[start:body.index('"', start)]

    client.post("/quiz", data={"exercise_id": exercise_id,
                               "answer_index": "not-a-number",
                               "csrf_token": csrf_token}, follow_redirects=True)
    # grading failed → nothing stored
    assert storage.fetch_quiz_results(app, limit=10) == []


def test_quiz_finishes_and_shows_summary(client, csrf_token):
    client.get("/quiz?restart=1")
    body = client.get("/quiz").data.decode("utf-8", "replace")
    import re
    total = 0
    while total < 25:
        match = re.search(r'name="exercise_id" value="([^"]+)"', body)
        if not match:
            break
        response = client.post("/quiz", data={
            "exercise_id": match.group(1), "answer_index": "0",
            "signs": ["0"], "csrf_token": csrf_token})
        body = response.data.decode("utf-8", "replace")
        total += 1
    assert "Quiz finished" in body
    assert total >= 10


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

def test_create_campaign(client, csrf_token, app):
    response = client.post("/campaigns", data={
        "name": "Test Awareness Drive", "description": "fictional",
        "scenario_count": "3", "status": "Draft", "csrf_token": csrf_token},
        follow_redirects=True)
    assert response.status_code == 200
    assert "Test Awareness Drive" in response.data.decode("utf-8", "replace")
    names = [c["name"] for c in storage.list_campaigns(app)]
    assert "Test Awareness Drive" in names


@pytest.mark.parametrize("payload", [
    {"name": "", "scenario_count": "3", "status": "Draft"},          # no name
    {"name": "X" * 200, "scenario_count": "3", "status": "Draft"},   # name too long
    {"name": "Ok", "scenario_count": "0", "status": "Draft"},        # bad count
    {"name": "Ok", "scenario_count": "3", "status": "Weird"},        # bad status
])
def test_invalid_campaign_input_is_rejected(client, csrf_token, app, payload):
    data = dict(payload)
    data["csrf_token"] = csrf_token
    before = len(storage.list_campaigns(app))
    response = client.post("/campaigns", data=data, follow_redirects=True)
    assert response.status_code == 200
    assert len(storage.list_campaigns(app)) == before


def test_start_campaign_opens_quiz(client, csrf_token, app):
    storage.create_campaign(app, "Quiz Linked", "d", 5, "Active")
    campaign = [c for c in storage.list_campaigns(app) if c["name"] == "Quiz Linked"][0]
    response = client.get(f"/campaigns/{campaign['id']}/start", follow_redirects=True)
    assert response.status_code == 200
    assert b"Quiz Linked" in response.data


def test_start_missing_campaign_returns_404(client):
    assert client.get("/campaigns/9999/start").status_code == 404


def test_delete_campaign(client, csrf_token, app):
    cid = storage.create_campaign(app, "Temporary", "d", 2, "Draft")
    response = client.post(f"/campaigns/{cid}/delete", data={"csrf_token": csrf_token},
                           follow_redirects=True)
    assert response.status_code == 200
    assert storage.get_campaign(app, cid) is None


# ---------------------------------------------------------------------------
# History / clearing records
# ---------------------------------------------------------------------------

def test_history_page_lists_records(client, csrf_token, app):
    client.post("/api/analyze", json={"message": PHISH_MESSAGE},
                headers={"X-CSRF-Token": csrf_token})
    body = client.get("/history").data.decode("utf-8", "replace")
    assert "Activity log" in body
    assert "Clear demonstration records" in body


def test_clear_all_records(client, csrf_token, app):
    client.post("/api/analyze", json={"message": PHISH_MESSAGE},
                headers={"X-CSRF-Token": csrf_token})
    response = client.post("/history", data={"mode": "all", "csrf_token": csrf_token},
                           follow_redirects=True)
    assert response.status_code == 200
    assert storage.fetch_analyses(app, limit=50) == []


def test_unknown_clear_mode_is_ignored(client, csrf_token, app):
    client.post("/api/analyze", json={"message": ORDINARY_MESSAGE},
                headers={"X-CSRF-Token": csrf_token})
    client.post("/history", data={"mode": "nonsense", "csrf_token": csrf_token},
                follow_redirects=True)
    assert len(storage.fetch_analyses(app, limit=50)) == 1


# ---------------------------------------------------------------------------
# Stats API
# ---------------------------------------------------------------------------

def test_stats_api_shape(client):
    payload = client.get("/api/stats").get_json()
    assert payload["ok"] is True
    stats = payload["stats"]
    for key in ("total_analyses", "flagged", "completed_exercises",
                "quiz_accuracy", "awareness_score", "common_indicators"):
        assert key in stats
    assert 0 <= stats["quiz_accuracy"] <= 100
    assert 0 <= stats["awareness_score"] <= 100


# ---------------------------------------------------------------------------
# Security checks
# ---------------------------------------------------------------------------

def test_user_text_is_escaped_when_displayed(client, csrf_token):
    payload = client.post("/api/analyze",
                          json={"message": "<script>alert('xss')</script> "
                                            "verify your password now"},
                          headers={"X-CSRF-Token": csrf_token}).get_json()
    assert "<script>" not in payload["html"].replace("&lt;script&gt;", "")
    assert "&lt;script&gt;" in payload["html"] or "<script>" not in payload["html"]


def test_form_post_without_csrf_token_is_rejected(app, client):
    app.config["CSRF_ENABLED"] = True
    with client.session_transaction() as sess:
        sess["csrf_token"] = "server-side-token"
    response = client.post("/analyze", data={"message": "hello"})
    assert response.status_code == 403
    app.config["CSRF_ENABLED"] = False


def test_api_post_without_csrf_token_is_rejected(app, client):
    app.config["CSRF_ENABLED"] = True
    with client.session_transaction() as sess:
        sess["csrf_token"] = "server-side-token"
    response = client.post("/api/analyze", json={"message": "hello"})
    assert response.status_code == 400
    assert "token" in response.get_json()["error"].lower()
    app.config["CSRF_ENABLED"] = False


def test_api_post_with_valid_csrf_token_is_allowed(app, client):
    app.config["CSRF_ENABLED"] = True
    with client.session_transaction() as sess:
        sess["csrf_token"] = "server-side-token"
    response = client.post("/api/analyze", json={"message": ORDINARY_MESSAGE},
                           headers={"X-CSRF-Token": "server-side-token"})
    assert response.status_code == 200
    app.config["CSRF_ENABLED"] = False


def test_no_passwords_are_stored(client, csrf_token, app):
    secret = "MyVeryOwnPassword123!"
    client.post("/api/analyze",
                json={"message": f"Dear user, confirm your password {secret} now"},
                headers={"X-CSRF-Token": csrf_token})
    conn = storage.connect(config.TestConfig.DATABASE_PATH)
    try:
        rows = conn.execute("SELECT * FROM analyses").fetchall()
    finally:
        conn.close()
    assert rows, "the analysis should have been stored"
    for row in rows:
        joined = " ".join(str(v) for v in dict(row).values())
        assert secret not in joined
        assert len(joined) < 700, "only a short snippet should be stored"
