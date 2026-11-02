"""
phishlab/auth.py
----------------
Multi-user authentication: local email/password accounts and
"Sign in with Google" via OpenID Connect (Authlib).

The User class is a thin wrapper around a row from the `users` table so
Flask-Login can manage the session.  Passwords are hashed with Werkzeug's
scrypt-based hasher (ships with Flask).  Google accounts are matched by
e-mail; the first Google sign-in creates the account automatically.
Password-reset links are random one-time tokens, stored only as hashes and
valid for RESET_TTL_SECONDS.
"""

import hashlib
import secrets
import time

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from phishlab import storage

# How long a password-reset link stays valid.
RESET_TTL_SECONDS = 30 * 60


class User(UserMixin):
    """One row from the `users` table, exposed to Flask-Login."""

    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.name = row["name"] or row["email"].split("@")[0]
        self.password_hash = row["password_hash"]
        self.provider = row["provider"]
        self.created_at = row["created_at"]

    def display_name(self):
        return self.name or self.email.split("@")[0]


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password):
    return generate_password_hash(password)


def verify_password(user_row, password):
    """Return True when the password matches the stored hash."""
    if not user_row or not user_row.get("password_hash") or not password:
        return False
    return check_password_hash(user_row["password_hash"], password)


# ---------------------------------------------------------------------------
# Account lookup / creation
# ---------------------------------------------------------------------------

def authenticate(app, email, password):
    """Return a User on success, None on failure (no information leaked)."""
    row = storage.get_user_by_email(app, email)
    if row is None or not verify_password(row, password):
        return None
    return User(row)


def signup_local(app, name, email, password):
    """
    Create a local (email + password) account.
    Raises ValueError with a user-friendly message on validation problems.
    """
    email = (email or "").strip().lower()
    name = (name or "").strip()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        raise ValueError("Please enter a valid e-mail address.")
    if storage.get_user_by_email(app, email) is not None:
        raise ValueError("An account with that e-mail address already exists. Try logging in.")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    storage.create_user(app, email, name, hash_password(password), provider="local")
    return User(storage.get_user_by_email(app, email))


def find_or_create_google_user(app, email, name):
    """
    Match an existing account by e-mail, or create a Google-provider account
    on first sign-in.  Returns a User.
    """
    email = (email or "").strip().lower()
    row = storage.get_user_by_email(app, email)
    if row is None:
        storage.create_user(app, email, name or email.split("@")[0],
                            password_hash=None, provider="google")
        row = storage.get_user_by_email(app, email)
    return User(row)


# ---------------------------------------------------------------------------
# Password-reset tokens (local app — the "e-mailed" link is shown on screen)
# ---------------------------------------------------------------------------

def _hash_token(token):
    """Only the hash of a reset token ever touches the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_reset_token(app, user_row):
    """Issue a fresh one-time reset token; returns the raw value for the link."""
    token = secrets.token_urlsafe(32)
    storage.store_password_reset(app, user_row["id"], _hash_token(token),
                                 int(time.time()), RESET_TTL_SECONDS)
    return token


def peek_reset_token(app, token):
    """Return the user row for a still-valid, unused token — or None."""
    if not token:
        return None
    return storage.get_password_reset(app, _hash_token(token),
                                      int(time.time()), RESET_TTL_SECONDS)


def apply_new_password(app, token, password, confirm):
    """
    Validate a reset request and store the new password hash.
    Raises ValueError with a user-friendly message on any problem.
    """
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if password != confirm:
        raise ValueError("The two passwords do not match.")
    row = peek_reset_token(app, token)
    if row is None:
        raise ValueError("That reset link is invalid or has expired. Request a new one.")
    storage.update_user_password(app, row["id"], hash_password(password))
    storage.consume_password_reset(app, _hash_token(token), email=row["email"])


# ---------------------------------------------------------------------------
# Google OAuth client registration (Authlib)
# ---------------------------------------------------------------------------

def register_google_oauth(app, oauth):
    """
    Attach a Google client to the Authlib OAuth object.
    Returns the client, or None when credentials are not configured.
    """
    client_id = app.config.get("GOOGLE_CLIENT_ID", "")
    client_secret = app.config.get("GOOGLE_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None
    return oauth.register(
        name="google",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=app.config.get(
            "GOOGLE_DISCOVERY_URL",
            "https://accounts.google.com/.well-known/openid-configuration",
        ),
        client_kwargs={"scope": "openid email profile"},
    )
