"""
config.py
---------
Central configuration for PhishLab AI.

Everything that a student might want to change (paths, limits, secret key)
lives here so the rest of the code stays simple.

SECURITY NOTE:
    The secret key is used to sign CSRF tokens (cross-site request forgery
    protection).  In a real deployment you would load it from an environment
    variable.  For this local college project we generate a random key that
    changes every time the app restarts, which is safe for local use and
    keeps secrets OUT of the source code.
"""

import os
import secrets
import sys

# ---------------------------------------------------------------------------
# Folder locations
# ---------------------------------------------------------------------------
# When frozen by PyInstaller, bundled assets (templates, static, models,
# dataset) live in the temporary extraction folder (sys._MEIPASS).
# The SQLite database must go somewhere writable, so we put it next to the
# .exe on Windows, or in the user's home folder otherwise.
if getattr(sys, "frozen", False):
    BUNDLE_DIR = sys._MEIPASS
    if os.name == "nt":
        BASE_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                                "PhishLabAI")
    else:
        BASE_DIR = os.path.join(os.path.expanduser("~"), ".phishlab")
    os.makedirs(BASE_DIR, exist_ok=True)
else:
    BUNDLE_DIR = os.path.abspath(os.path.dirname(__file__))
    BASE_DIR = BUNDLE_DIR


class Config:
    """Default configuration used when running the application."""

    # --- Security ---------------------------------------------------------
    # Load from environment when available; otherwise use a random key.
    # A random key simply means saved sessions are invalidated on restart,
    # which is completely fine for a local educational project.
    SECRET_KEY = os.environ.get("PHISHLAB_SECRET_KEY") or secrets.token_hex(32)

    # Never enable debug mode on a public network.
    DEBUG = False
    TESTING = False

    # Cross-site request forgery protection (hidden token on every form).
    CSRF_ENABLED = True

    # --- Storage (writable) ------------------------------------------------
    # When frozen, this lands in %LOCALAPPDATA%\PhishLabAI (or ~/.phishlab).
    DATABASE_PATH = os.path.join(BASE_DIR, "phishlab.db")

    # --- Machine-learning artefacts (read-only, bundled with the app) ------
    MODEL_PATH = os.path.join(BUNDLE_DIR, "models", "model.joblib")
    VECTORIZER_PATH = os.path.join(BUNDLE_DIR, "models", "vectorizer.joblib")
    METRICS_PATH = os.path.join(BUNDLE_DIR, "models", "metrics.json")
    DATASET_PATH = os.path.join(BUNDLE_DIR, "data", "sample_messages.csv")

    # --- Input limits (helps validate and reject malformed input) --------
    MAX_EMAIL_LENGTH = 20_000       # characters of message text
    MAX_URL_LENGTH = 2_048          # characters of a URL
    MAX_NAME_LENGTH = 80            # campaign name
    MAX_DESCRIPTION_LENGTH = 500    # campaign description

    # How much data to keep in the "recent activity" table.
    ACTIVITY_LIMIT = 100

    # Seed clearly-labelled demonstration records on first start.
    SEED_DEMO = True

    # --- Google OAuth (Sign in with Google) --------------------------------
    # Create credentials at https://console.cloud.google.com/apis/credentials
    # (OAuth client ID, type "Web application"), then either export these two
    # environment variables or paste the values here for local testing.
    # Authorised redirect URI must exactly match:  <APP_URL>/auth/google/callback
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    # OpenID Connect discovery document (do not change unless Google changes it).
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


class TestConfig(Config):
    """Configuration used by the automated tests (separate SQLite file)."""

    TESTING = True
    SEED_DEMO = False
    DATABASE_PATH = os.path.join(BASE_DIR, "test_phishlab.db")
    # Tests that post forms would otherwise have to keep a live session cookie;
    # one dedicated test switches protection back on to prove it works.
    CSRF_ENABLED = False
    # Rate limits would break tests that hit the same route many times.
    RATELIMIT_ENABLED = False
