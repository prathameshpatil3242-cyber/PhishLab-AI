"""
tests/conftest.py
-----------------
Shared pytest fixtures.

Every test uses a SEPARATE SQLite file (test_phishlab.db) that is deleted and
re-created before each test, so tests never touch your real data.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config                      # noqa: E402
from app import app as flask_app   # noqa: E402
from phishlab import storage       # noqa: E402


@pytest.fixture()
def app():
    """Flask application configured for testing with a fresh database."""
    flask_app.config.from_object(config.TestConfig)
    flask_app.config["CSRF_ENABLED"] = False

    db_path = config.TestConfig.DATABASE_PATH
    if os.path.exists(db_path):
        os.remove(db_path)
    storage.init_db(flask_app)

    yield flask_app

    flask_app.config["CSRF_ENABLED"] = False
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture()
def client(app):
    """Flask test client (a fake browser)."""
    return app.test_client()


@pytest.fixture()
def csrf_token(app, client):
    """A valid CSRF token plus a helper to post forms with it."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = "pytest-token"
    return "pytest-token"


@pytest.fixture()
def login(app, client):
    """Create a local account and sign the test client in (for gated pages)."""
    from phishlab import auth as auth_mod

    email = "tester@example.com"
    storage.create_user(app, email, "Test User",
                        auth_mod.hash_password("password123"), provider="local")
    response = client.post("/login", data={"email": email, "password": "password123"},
                           follow_redirects=True)
    assert response.status_code == 200, "login fixture failed to sign in"
    return email
