"""
phishlab/storage.py
-------------------
All database (SQLite) operations live in this file.

Using one small module keeps SQL out of the page code and makes it easy to
follow the data flow.  Every query uses *parameterised* statements
(? placeholders) so user input is never mixed into SQL text.

Tables
------
analyses         -> results of email / URL analyses (rule engine + ML)
quiz_results     -> awareness training scores
campaigns        -> local educational exercise campaigns
activity         -> recent activity log (no passwords, no secrets)
users            -> local / Google accounts (passwords stored only as hashes)
password_resets  -> one-time password reset tokens (SHA-256 of the token)
"""

import json
import os
import sqlite3
from datetime import datetime

from flask import g, has_app_context

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def connect(path):
    """Open a SQLite connection with row objects accessible by column name."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db(app):
    """
    Return a per-request database connection (stored on flask.g).
    The connection is closed automatically when the request finishes.

    When no application context exists (scripts, pytest helpers) a fresh
    short-lived connection is returned instead, so helper functions keep
    working outside a running web request.
    """
    if not has_app_context():
        return connect(app.config["DATABASE_PATH"])
    if "_db" not in g:
        g._db = connect(app.config["DATABASE_PATH"])
        g._db_close = True
    return g._db


def close_db(_exc=None):
    """Close the request's connection if one was opened."""
    conn = g.pop("_db", None)
    if conn is not None:
        conn.close()


def now():
    """Local timestamp used for every record (easy for students to read)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,                 -- 'email' or 'url'
    title         TEXT NOT NULL,                 -- short, non-sensitive snippet
    classification TEXT NOT NULL,
    risk_score    INTEGER NOT NULL,
    indicators    TEXT NOT NULL,                 -- JSON list of indicator names
    engine        TEXT NOT NULL DEFAULT 'rules', -- 'rules', 'ml' or 'rules+ml'
    source        TEXT NOT NULL DEFAULT 'live',  -- 'live' or 'demo'
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quiz_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    exercise_id   TEXT NOT NULL,
    topic         TEXT NOT NULL,
    correct       INTEGER NOT NULL,              -- 1 = correct, 0 = wrong
    points        INTEGER NOT NULL,
    source        TEXT NOT NULL DEFAULT 'live',
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    scenario_count INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'Draft',
    completed      INTEGER NOT NULL DEFAULT 0,   -- participants finished
    participants   INTEGER NOT NULL DEFAULT 0,
    source         TEXT NOT NULL DEFAULT 'live',
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL,     -- e.g. 'Email analysis'
    ref        TEXT NOT NULL,     -- short identifier / snippet
    result     TEXT NOT NULL,     -- short outcome text
    source     TEXT NOT NULL DEFAULT 'live',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT,                          -- NULL for Google-only accounts
    provider      TEXT NOT NULL DEFAULT 'local', -- 'local' or 'google'
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,             -- SHA-256 of the raw token
    created_at INTEGER NOT NULL,                 -- unix time (expiry is checked on read)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""


def init_db(app):
    """Create tables (if missing) and seed demonstration records once."""
    db_path = app.config["DATABASE_PATH"]
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        count = conn.execute("SELECT COUNT(*) AS c FROM activity").fetchone()["c"]
        if count == 0 and app.config.get("SEED_DEMO", True):
            seed_demo_data(conn)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Demo (seeded) data — clearly marked with source = 'demo'
# ---------------------------------------------------------------------------

def seed_demo_data(conn):
    """
    Insert clearly-labelled demonstration records so the dashboard is not
    empty on first run.  These are FICTIONAL numbers for presentation only.
    """
    demo_analyses = [
        ("email", "From: alerts@amaz0n-billing.net …", "Potential phishing", 78,
         ["credential", "urgency", "sender"], "rules+ml"),
        ("email", "From: team@tkiet.example.edu …", "No obvious indicators", 8,
         ["greeting"], "rules"),
        ("url", "http://192.168.10.44/verify/account/login", "Elevated indicators — do not trust blindly", 71,
         ["Hostname is an IP address", "Sensitive words in the path"], "rules"),
        ("email", "From: support@paypa1-secure.com …", "Potential phishing", 84,
         ["credential", "sender", "impersonation", "urgency"], "rules+ml"),
        ("url", "https://tkiet.example.edu/notice", "Few static indicators found", 4,
         ["URL scheme"], "rules"),
        ("email", "Congratulations! You have won a free gift card…", "Needs review", 38,
         ["reward", "grammar"], "rules"),
        ("url", "https://secure-paypal.login.verify-account.top/session",
         "Elevated indicators — do not trust blindly", 62,
         ["Misleading domain string", "Sensitive words in the path"], "rules"),
        ("email", "Dear customer, your account will be suspended within 24 hours…",
         "Potential phishing", 66, ["urgency", "greeting", "verification"], "rules"),
    ]
    for kind, title, cls, score, inds, engine in demo_analyses:
        conn.execute(
            "INSERT INTO analyses (kind, title, classification, risk_score, indicators, "
            "engine, source, created_at) VALUES (?,?,?,?,?,?, 'demo', ?)",
            (kind, title, cls, score, json.dumps(inds), engine,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

    demo_quiz = [
        ("q-urgent-deadline", "Urgent deadline message", 1, 10),
        ("q-fake-invoice", "Fake invoice attachment", 1, 10),
        ("q-legit-newsletter", "Legitimate newsletter", 1, 10),
        ("q-prize-scam", "Prize notification scam", 0, 0),
    ]
    for ex_id, topic, correct, points in demo_quiz:
        conn.execute(
            "INSERT INTO quiz_results (exercise_id, topic, correct, points, source, created_at) "
            "VALUES (?,?,?,?,'demo',?)",
            (ex_id, topic, correct, points, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

    demo_campaigns = [
        ("Hostel Wi-Fi Awareness Drive", "Short quiz set about fake Wi-Fi login pages.", 5,
         "Active", 18, 24),
        ("Freshers Cyber Week — Email Spotting", "Fictional messages for first-year students.", 8,
         "Completed", 42, 42),
        ("Staff Phishing Refresher", "Password/OTP themed scenarios for staff demo.", 6,
         "Draft", 0, 0),
    ]
    for name, desc, cnt, status, completed, participants in demo_campaigns:
        conn.execute(
            "INSERT INTO campaigns (name, description, scenario_count, status, completed, "
            "participants, source, created_at) VALUES (?,?,?,?,?,?,'demo',?)",
            (name, desc, cnt, status, completed, participants,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

    demo_activity = [
        ("Email analysis", "msg-DEMO-004", "Flagged as potential phishing (84/100)"),
        ("URL analysis", "url-DEMO-003", "Preliminary score 71/100 — high indicators"),
        ("Quiz completed", "q-legit-newsletter", "Correct (+10 points)"),
        ("Campaign created", "Hostel Wi-Fi Awareness Drive", "Status: Active"),
        ("Model evaluated", "naive-bayes-v1", "Demonstration metrics loaded"),
    ]
    for t, ref, res in demo_activity:
        conn.execute(
            "INSERT INTO activity (type, ref, result, source, created_at) "
            "VALUES (?,?,?,'demo',?)",
            (t, ref, res, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )


# ---------------------------------------------------------------------------
# Insert helpers
# ---------------------------------------------------------------------------

def add_analysis(app, kind, title, classification, risk_score, indicator_names,
                 engine="rules", source="live"):
    """Store one analysis result and add a matching activity entry."""
    conn = get_db(app)
    title = (title or "")[:120]
    conn.execute(
        "INSERT INTO analyses (kind, title, classification, risk_score, indicators, "
        "engine, source, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (kind, title, classification, int(risk_score),
         json.dumps(list(indicator_names)), engine, source, now()),
    )
    log_activity(conn, f"{'Email' if kind == 'email' else 'URL'} analysis",
                 title[:40] or kind, f"Score {risk_score}/100 — {classification}", source)
    conn.commit()


def log_activity(conn, act_type, ref, result, source="live"):
    """Append one row to the activity log (trimmed to keep the table small)."""
    conn.execute(
        "INSERT INTO activity (type, ref, result, source, created_at) VALUES (?,?,?,?,?)",
        (act_type, (ref or "")[:80], (result or "")[:160], source, now()),
    )
    conn.execute(
        "DELETE FROM activity WHERE id NOT IN "
        "(SELECT id FROM activity ORDER BY id DESC LIMIT 200)"
    )


def add_quiz_result(app, exercise_id, topic, correct, points, source="live"):
    conn = get_db(app)
    conn.execute(
        "INSERT INTO quiz_results (exercise_id, topic, correct, points, source, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (exercise_id, topic, 1 if correct else 0, int(points), source, now()),
    )
    log_activity(conn, "Quiz answered", exercise_id,
                 f"{'Correct' if correct else 'Incorrect'} (+{points} points)", source)
    conn.commit()


# ---------------------------------------------------------------------------
# Campaign helpers
# ---------------------------------------------------------------------------

def list_campaigns(app, source=None):
    conn = get_db(app)
    if source:
        rows = conn.execute(
            "SELECT * FROM campaigns WHERE source=? ORDER BY id DESC", (source,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM campaigns ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_campaign(app, campaign_id):
    conn = get_db(app)
    row = conn.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
    return dict(row) if row else None


def create_campaign(app, name, description, scenario_count, status="Draft", source="live"):
    conn = get_db(app)
    cur = conn.execute(
        "INSERT INTO campaigns (name, description, scenario_count, status, completed, "
        "participants, source, created_at) VALUES (?,?,?,?,0,0,?,?)",
        (name, description, int(scenario_count), status, source, now()),
    )
    log_activity(conn, "Campaign created", name[:60], f"Status: {status}", source)
    conn.commit()
    return cur.lastrowid


def update_campaign(app, campaign_id, **fields):
    """Update any subset of campaign columns (parameterised)."""
    allowed = {"name", "description", "scenario_count", "status", "completed", "participants"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    conn = get_db(app)
    cols = ", ".join(f"{k}=?" for k in updates)
    conn.execute(f"UPDATE campaigns SET {cols} WHERE id=?",
                 (*updates.values(), campaign_id))
    conn.commit()
    return True


def delete_campaign(app, campaign_id):
    conn = get_db(app)
    row = conn.execute("SELECT name FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
    conn.execute("DELETE FROM campaigns WHERE id=?", (campaign_id,))
    if row:
        log_activity(conn, "Campaign deleted", row["name"][:60], "Removed by user")
    conn.commit()
    return row is not None


# ---------------------------------------------------------------------------
# Read helpers (used by analytics / dashboard)
# ---------------------------------------------------------------------------

def fetch_analyses(app, limit=50):
    conn = get_db(app)
    rows = conn.execute(
        "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_quiz_results(app, limit=200):
    conn = get_db(app)
    rows = conn.execute(
        "SELECT * FROM quiz_results ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_activity(app, limit=100):
    conn = get_db(app)
    rows = conn.execute(
        "SELECT * FROM activity ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def fetch_recent_analyses(app, limit=6):
    return fetch_analyses(app, limit)


# ---------------------------------------------------------------------------
# Reset helpers
# ---------------------------------------------------------------------------

def reset_demo_records(app):
    """Delete every seeded demonstration record (keeps the user's own data)."""
    conn = get_db(app)
    deleted = 0
    for table in ("analyses", "quiz_results", "campaigns", "activity"):
        cur = conn.execute(f"DELETE FROM {table} WHERE source='demo'")
        deleted += cur.rowcount
    log_activity(conn, "Data reset", "demo-records", f"{deleted} demonstration record(s) removed")
    conn.commit()
    return deleted


def reset_all_records(app):
    """Delete everything — used by the Settings page 'reset all data'."""
    conn = get_db(app)
    total = 0
    for table in ("analyses", "quiz_results", "campaigns", "activity"):
        cur = conn.execute(f"DELETE FROM {table}")
        total += cur.rowcount
    conn.execute(
        "INSERT INTO activity (type, ref, result, source, created_at) VALUES (?,?,?,?,?)",
        ("Data reset", "all-records", "All local records cleared", "live", now()),
    )
    conn.commit()
    return total


# ---------------------------------------------------------------------------
# User account helpers (multi-user authentication)
# ---------------------------------------------------------------------------

def create_user(app, email, name, password_hash=None, provider="local"):
    """Insert a new user row.  Raises sqlite3.IntegrityError if email exists."""
    conn = get_db(app)
    cur = conn.execute(
        "INSERT INTO users (email, name, password_hash, provider, created_at) "
        "VALUES (?,?,?,?,?)",
        (email.lower(), name, password_hash, provider, now()),
    )
    log_activity(conn, "Account created", email.lower()[:60],
                 f"Signed up via {provider}")
    conn.commit()
    return cur.lastrowid


def get_user_by_id(app, user_id):
    conn = get_db(app)
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_email(app, email):
    conn = get_db(app)
    row = conn.execute("SELECT * FROM users WHERE email=?", ((email or "").lower(),)).fetchone()
    return dict(row) if row else None


def update_user_password(app, user_id, password_hash):
    conn = get_db(app)
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))
    conn.commit()


def count_users(app):
    conn = get_db(app)
    return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]


# ---------------------------------------------------------------------------
# Password-reset tokens (one-time, stored only as a SHA-256 hash)
# ---------------------------------------------------------------------------

def store_password_reset(app, user_id, token_hash, created_at, ttl_seconds):
    """
    Save a fresh reset token for a user and drop any older unused ones,
    so at most one valid link exists per account at any time.
    """
    conn = get_db(app)
    conn.execute("DELETE FROM password_resets WHERE user_id=? OR created_at < ?",
                 (user_id, created_at - ttl_seconds))
    conn.execute(
        "INSERT INTO password_resets (user_id, token_hash, created_at) VALUES (?,?,?)",
        (user_id, token_hash, created_at),
    )
    conn.commit()


def get_password_reset(app, token_hash, now_ts, ttl_seconds):
    """Return the user row for a still-valid token, or None."""
    conn = get_db(app)
    row = conn.execute(
        "SELECT u.* FROM password_resets r JOIN users u ON u.id = r.user_id "
        "WHERE r.token_hash=? AND r.created_at >= ?",
        (token_hash, now_ts - ttl_seconds),
    ).fetchone()
    return dict(row) if row else None


def consume_password_reset(app, token_hash, email=""):
    """Delete a reset token once it has been used (tokens are one-time)."""
    conn = get_db(app)
    conn.execute("DELETE FROM password_resets WHERE token_hash=?", (token_hash,))
    if email:
        log_activity(conn, "Password reset", email[:60], "Password changed via reset link")
    conn.commit()
