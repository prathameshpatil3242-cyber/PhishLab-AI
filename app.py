"""
app.py
------
The Flask web application for PhishLab AI.

Run it with:      python app.py
Then open:        http://127.0.0.1:5000

What this file does
    * creates the Flask app,
    * initialises the local SQLite database,
    * defines every page (route) and every JSON API endpoint,
    * applies simple security protections (CSRF tokens, input limits),
    * keeps the rule engine and the machine-learning model clearly separate.

SAFETY: this application never opens submitted URLs, never executes message
content and never sends data anywhere outside this computer.
"""

import json
import re
import secrets
from urllib.parse import urlparse

from authlib.integrations.flask_client import OAuth
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)

import config
from phishlab import analyzer, awareness_data, auth as auth_mod, metrics, storage, train_model
from phishlab import url_analyzer as urlmod

# ---------------------------------------------------------------------------
# Application factory-ish setup (kept simple and linear for beginners)
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(config.Config)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024      # 512 KB request limit

# Make sure the database and tables exist before the first page is served.
storage.init_db(app)

# ---------------------------------------------------------------------------
# Login manager (Flask-Login) + Google OAuth client (Authlib)
# ---------------------------------------------------------------------------

login_manager = LoginManager(app)
login_manager.login_view = "login_page"          # redirect target for @login_required
login_manager.login_message_category = "error"
login_manager.session_protection = "basic"

@login_manager.user_loader
def load_user(user_id):
    """Reload the signed-in user from SQLite on every request."""
    try:
        row = storage.get_user_by_id(app, int(user_id))
    except (TypeError, ValueError):
        return None
    return auth_mod.User(row) if row else None


oauth = OAuth(app)
google_client = auth_mod.register_google_oauth(app, oauth)

# ---------------------------------------------------------------------------
# Rate limiting (Flask-Limiter)
# ---------------------------------------------------------------------------
# One budget per client IP address.  No global default limit is applied —
# limits are attached to specific routes with the @limiter.limit decorator.
# Counters live in process memory, which is enough for this local app.

limiter = Limiter(
    key_func=get_remote_address,   # throttle per IP address
    app=app,
    default_limits=[],             # only the routes decorated below are limited
    storage_uri="memory://",
    headers_enabled=True,          # expose X-RateLimit-* / Retry-After headers
)


@app.errorhandler(RateLimitExceeded)
def _rate_limited(_err):
    """Friendly response when a client exceeds its request budget."""
    message = ("Too many requests from your IP address. "
               "Please wait about a minute and try again.")
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error=message), 429
    flash(message, "error")
    return redirect(request.referrer or url_for("dashboard")), 429


# ---------------------------------------------------------------------------
# CSRF (cross-site request forgery) protection
# ---------------------------------------------------------------------------
# Every state-changing request must carry the token that we placed in the
# session cookie.  HTML forms carry it in a hidden field; the JavaScript
# helpers send it as the X-CSRF-Token header.

def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = _csrf_token


@app.before_request
def csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    if not app.config.get("CSRF_ENABLED", True):
        return None
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if not sent or sent != session.get("csrf_token"):
        if request.path.startswith("/api/"):
            return jsonify(ok=False, error="Security token missing or invalid. Reload the page and try again."), 400
        return render_template(
            "error.html", code=403,
            message="Security token missing or invalid. Please go back, reload "
                    "the page and submit the form again."), 403
    return None


@app.context_processor
def inject_globals():
    """Values every template can use (page title, model status, flash helper)."""
    model_status = train_model.status(app.config["METRICS_PATH"], app.config["MODEL_PATH"])
    if "pid" not in session:
        session["pid"] = secrets.token_hex(3).upper()
    return {
        "model_status": model_status,
        "nav_section": request.endpoint or "",
        "participant_id": session["pid"],
        "current_user": current_user,
        "google_enabled": google_client is not None,
    }


@app.errorhandler(404)
def not_found(_err):
    return render_template("error.html", code=404,
                           message="That page does not exist."), 404


@app.errorhandler(413)
def too_large(_err):
    message = "The text you submitted is too large. Please shorten it and try again."
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error=message), 413
    flash(message, "error")
    return redirect(request.referrer or url_for("dashboard")), 413


# ---------------------------------------------------------------------------
# Small validation helpers
# ---------------------------------------------------------------------------

def _clean_text(raw, limit_name, limit_value):
    """Trim and validate pasted message text. Returns (text, error)."""
    text = (raw or "").strip()
    if not text:
        return "", f"Please paste some text into the {limit_name} box before analysing."
    if len(text) > limit_value:
        return "", (f"Your text is {len(text):,} characters long. "
                    f"The maximum accepted length is {limit_value:,} characters.")
    return text, None


def _clean_url(raw):
    """
    Validate a URL *as text only*.  Nothing is fetched, resolved or opened.
    Returns (url, error).
    """
    url = (raw or "").strip()
    if not url:
        return "", "Please enter a URL before analysing."
    if len(url) > app.config["MAX_URL_LENGTH"]:
        return "", f"URL is too long (maximum {app.config['MAX_URL_LENGTH']} characters)."
    if any(ch in url for ch in ("\n", "\r", "\x00", " ", "\t")):
        return "", "A URL must not contain spaces or line breaks."

    working = url if "://" in url or url.startswith("//") else "http://" + url
    try:
        parsed = urlparse(working)
        host = parsed.hostname or ""
    except Exception:
        return "", "That does not look like a valid URL."

    if not host:
        return "", "That does not look like a valid URL — no website address was found."
    if " " in host or not host.replace(":", "").replace("[", "").replace("]", ""):
        return "", "That does not look like a valid URL."
    # A normal host is either an IP address, localhost, or a name with a dot.
    is_ip = host.count(".") == 3 and all(p.isdigit() and int(p) <= 255 for p in host.split("."))
    if "." not in host and host.lower() != "localhost" and not is_ip:
        return "", (f'"{host}" is not a complete website address. '
                    "Use a full address such as example.org or https://example.org/login.")
    return url, None


def _run_ml(text):
    """
    Ask the machine-learning model for a prediction.
    Returns a dict that always explains the state (never raises).
    """
    pipeline, err = train_model.load_model(app.config["MODEL_PATH"])
    if pipeline is None:
        return {"available": False, "error": err, "label": None, "probabilities": {},
                "note": ("Train the model to add an AI prediction. "
                         "Until then only the rule engine result is shown.")}
    try:
        label, probs = train_model.predict(pipeline, text)
    except train_model.TrainError as exc:
        return {"available": False, "error": str(exc), "label": None,
                "probabilities": {}, "note": "The model could not be used for this message."}

    confidence = max(probs.values()) if probs else 0.0
    return {
        "available": True,
        "error": None,
        "label": label,
        "probabilities": probs,
        "confidence": round(confidence, 4),
        "note": ("Model prediction from a small fictional dataset. "
                 "It can be wrong — treat it as one more opinion, not a verdict."),
    }


def _combine(rules_result, ml_result):
    """
    Keep the two engines separate but give the student one headline label.

    Documented decision table (educational heuristic, not a probability):
      * rule score >= 55 and model says phishing  -> Potential phishing
      * rule score >= 55 and model missing/other  -> Needs manual review
      * rule score <  55 and model says phishing  -> Needs manual review
      * rule score <  55 and model says legit/none-> No obvious phishing indicators
    """
    rules_label = rules_result["classification"]
    score = rules_result["risk_score"]

    if not ml_result.get("available"):
        if score >= 55:
            headline, engine = "Potentially suspicious — do not trust blindly", "rules"
        elif score >= 25:
            headline, engine = "Needs manual review", "rules"
        else:
            headline, engine = "No obvious phishing indicators found", "rules"
        return headline, engine, ("Only the rule engine was used because no trained "
                                  "model is available yet.")

    ml_says_phish = ml_result["label"] == "phishing"
    if score >= 55 and ml_says_phish:
        return "Potentially suspicious — do not trust blindly", "rules+ml", (
            "Both the rule engine and the model point towards phishing indicators.")
    if score >= 55 or ml_says_phish:
        return "Needs manual review", "rules+ml", (
            "The rule engine and the model do not fully agree, so a human must decide.")
    return "No obvious phishing indicators found", "rules+ml", (
        "Neither the rule engine nor the model found strong indicators. "
        "That never guarantees a message is safe.")


def _safe_title(text, limit=80):
    """
    Short, redacted snippet used as the stored 'title' of an analysis.

    Anything that looks like a credential (password, OTP, PIN, card number)
    or an e-mail address is replaced with [removed] so that pasting a real
    message never writes secrets into the database.
    """
    snippet = re.sub(
        r"(password|pwd|otp|pin|ssn|cvv|card number|secret|token)\s*[:=]?\s*\S+",
        lambda m: m.group(1) + " [removed]", str(text or ""), flags=re.IGNORECASE)
    snippet = re.sub(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[removed-email]", snippet)
    snippet = re.sub(
        r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "[removed-card]", snippet)
    snippet = " ".join(snippet.split())
    return (snippet[: limit - 3] + "...") if len(snippet) > limit else snippet


def _record_analysis(kind, text, headline, score, indicator_names, engine, source="live"):
    """Store a short redacted snippet locally (SQLite)."""
    try:
        storage.add_analysis(app, kind, _safe_title(text), headline, score,
                             indicator_names, engine=engine, source=source)
    except Exception:
        # Never break the page because the optional local log failed.
        pass


# ---------------------------------------------------------------------------
# Authentication — Sign up / Log in / Google OAuth
# ---------------------------------------------------------------------------

def _safe_next(target):
    """Only allow same-site redirect targets after login (open-redirect guard)."""
    if not target:
        return url_for("dashboard")
    ref = urlparse(target)
    if ref.netloc or not target.startswith("/"):
        return url_for("dashboard")
    return target


@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    """Create a new local account (email + password)."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if password != confirm:
            flash("The two passwords do not match. Please retype them.", "error")
        else:
            try:
                user = auth_mod.signup_local(app, name, email, password)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                login_user(user)
                flash(f"Welcome, {user.display_name()}! Your account has been created.", "success")
                return redirect(_safe_next(request.args.get("next")))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("30 per minute")   # slows down password guessing per IP
def login_page():
    """Sign in with an existing local account."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        user = auth_mod.authenticate(app, email, password)
        if user is None:
            flash("Incorrect e-mail address or password.", "error")
        else:
            login_user(user, remember=remember)
            flash(f"Signed in as {user.display_name()}.", "success")
            return redirect(_safe_next(request.args.get("next")))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout_page():
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("dashboard"))


@app.route("/auth/google")
def auth_google():
    """Start the Google (OpenID Connect) sign-in flow."""
    if google_client is None:
        flash("Google sign-in is not configured. Set GOOGLE_CLIENT_ID and "
              "GOOGLE_CLIENT_SECRET in the environment, or use e-mail sign-up.", "error")
        return redirect(url_for("login_page"))
    redirect_uri = url_for("auth_google_callback", _external=True)
    return google_client.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def auth_google_callback():
    """Handle the redirect back from Google and sign the user in."""
    if google_client is None:
        flash("Google sign-in is not configured.", "error")
        return redirect(url_for("login_page"))
    try:
        token = google_client.authorize_access_token()
    except Exception:
        flash("Google sign-in failed (the response could not be verified). Please try again.", "error")
        return redirect(url_for("login_page"))

    info = token.get("userinfo") or {}
    email = (info.get("email") or "").strip().lower()
    name = info.get("name") or info.get("given_name") or ""
    if not email:
        flash("Google did not return an e-mail address for this account.", "error")
        return redirect(url_for("login_page"))

    user = auth_mod.find_or_create_google_user(app, email, name)
    login_user(user)
    flash(f"Signed in with Google as {user.display_name()}.", "success")
    return redirect(_safe_next(session.pop("google_next", None)))


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for("login_page"))
    stats = metrics.get_dashboard_stats(app)
    recent = storage.fetch_activity(app, limit=8)
    campaign_rows = storage.list_campaigns(app)[:5]
    return render_template("dashboard.html", stats=stats, recent=recent,
                           campaign_rows=campaign_rows)


@app.route("/analyze", methods=["GET", "POST"])
def analyze_page():
    """Message analysis page (the HTML form posts back to this same route)."""
    result = None
    error = None
    text = ""

    if request.method == "POST":
        raw = request.form.get("message", "")
        limit = app.config["MAX_EMAIL_LENGTH"]
        text, error = _clean_text(raw, "message", limit)

        if error is None:
            try:
                rules_result = analyzer.analyze_message(text)
            except ValueError as exc:
                error = str(exc)

        if error is None:
            ml_result = _run_ml(text)
            headline, engine, note = _combine(rules_result, ml_result)
            indicator_names = [i["name"] for i in rules_result["indicators"]]
            result = {
                "headline": headline,
                "engine": engine,
                "note": note,
                "rules": rules_result,
                "ml": ml_result,
            }
            _record_analysis("email", text, headline, rules_result["risk_score"],
                             indicator_names, engine)

    return render_template("analyze.html", result=result, error=error, text=text)


@app.route("/url", methods=["GET", "POST"])
def url_page():
    """URL analysis page (never visits the URL)."""
    result = None
    error = None
    url = ""

    if request.method == "POST":
        url, error = _clean_url(request.form.get("url", ""))
        if error is None:
            try:
                result = urlmod.analyze_url(url)
            except ValueError as exc:
                error, result = str(exc), None

        if result is not None:
            headline = result["classification"]
            _record_analysis("url", result["url"], headline,
                             result["risk_score"], _risk_check_names(result), "rules")

    return render_template("url_analyzer.html", result=result, error=error, url=url)


def _risk_check_names(result):
    return [c["name"] for c in result["checks"] if c["status"] != "ok"]


@app.route("/campaigns", methods=["GET", "POST"])
def campaigns_page():
    """Fictional, local-only awareness campaigns."""
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        status = request.form.get("status") or "Draft"
        try:
            scenario_count = int(request.form.get("scenario_count") or 0)
        except ValueError:
            scenario_count = 0

        if not name or len(name) > app.config["MAX_NAME_LENGTH"]:
            flash("Please give the campaign a short name (1-80 characters).", "error")
        elif len(description) > app.config["MAX_DESCRIPTION_LENGTH"]:
            flash("Description is too long (maximum 500 characters).", "error")
        elif status not in ("Draft", "Active", "Completed"):
            flash("Please choose a valid status.", "error")
        elif not (1 <= scenario_count <= 50):
            flash("Scenario count must be between 1 and 50.", "error")
        else:
            storage.create_campaign(app, name, description, scenario_count, status)
            flash(f'Campaign "{name}" created locally. No e-mail was sent to anyone.', "success")
        return redirect(url_for("campaigns_page"))

    campaigns = storage.list_campaigns(app)
    return render_template("campaigns.html", campaigns=campaigns,
                           categories=awareness_data.categories())


@app.route("/campaigns/<int:campaign_id>/delete", methods=["POST"])
def delete_campaign(campaign_id):
    if storage.delete_campaign(app, campaign_id):
        flash("Campaign deleted.", "success")
    else:
        flash("Campaign not found.", "error")
    return redirect(url_for("campaigns_page"))


@app.route("/campaigns/<int:campaign_id>/start")
def start_campaign(campaign_id):
    """Open the local quiz for a campaign (no e-mails, no external users)."""
    campaign = storage.get_campaign(app, campaign_id)
    if campaign is None:
        abort(404)
    session.pop("quiz", None)
    session["quiz"] = {"queue": [e["id"] for e in awareness_data.get_exercises()],
                       "index": 0, "score": 0, "max": 0,
                       "answers": [], "campaign_id": campaign["id"],
                       "campaign_name": campaign["name"]}
    flash(f'Starting the local quiz for "{campaign["name"]}". Nothing is sent anywhere.', "success")
    return redirect(url_for("quiz_page"))


@app.route("/quiz", methods=["GET", "POST"])
def quiz_page():
    """Interactive educational quiz — one fictional exercise at a time."""
    if request.args.get("restart") or "quiz" not in session:
        session["quiz"] = {"queue": [e["id"] for e in awareness_data.get_exercises()],
                           "index": 0, "score": 0, "max": 0,
                           "answers": [], "campaign_id": None, "campaign_name": None}

    quiz = session["quiz"]
    feedback = None
    exercise = None

    if request.method == "POST":
        feedback, exercise = _handle_quiz_submit(quiz)
        if exercise is None and feedback and feedback.get("finished"):
            return render_template("quiz.html", exercise=None, quiz=quiz,
                                   feedback=feedback, categories=awareness_data.categories(),
                                   exercises=awareness_data.get_exercises())

    if exercise is None:
        if quiz["index"] >= len(quiz["queue"]):
            return render_template("quiz.html", exercise=None, quiz=quiz,
                                   feedback={"finished": True}, categories=awareness_data.categories(),
                                   exercises=awareness_data.get_exercises())
        exercise = awareness_data.get_exercise(quiz["queue"][quiz["index"]])

    return render_template("quiz.html", exercise=exercise, quiz=quiz, feedback=feedback,
                           categories=awareness_data.categories(),
                           exercises=awareness_data.get_exercises())


def _handle_quiz_submit(quiz):
    """Grade one answer, save it locally, advance the queue."""
    exercise_id = request.form.get("exercise_id", "")
    exercise = awareness_data.get_exercise(exercise_id)
    if exercise is None:
        flash("Unknown exercise. Please start the quiz again.", "error")
        return None, None

    try:
        answer_index = int(request.form.get("answer_index", -1))
    except ValueError:
        answer_index = -1

    signs = []
    for value in request.form.getlist("signs"):
        try:
            signs.append(int(value))
        except ValueError:
            continue

    try:
        points, max_points, details = awareness_data.grade(exercise, signs, answer_index)
    except ValueError as exc:
        flash(str(exc), "error")
        return None, exercise

    quiz["score"] += points
    quiz["max"] += max_points
    quiz["answers"].append({"exercise": exercise["id"], "points": points,
                            "max": max_points, "correct": points >= max_points})
    try:
        storage.add_quiz_result(app, exercise["id"], exercise["topic"],
                                points >= max_points * 0.5, round(points))
    except Exception:
        pass

    quiz["index"] += 1
    finished = quiz["index"] >= len(quiz["queue"])

    if finished and quiz.get("campaign_id"):
        campaign = storage.get_campaign(app, quiz["campaign_id"])
        if campaign:
            storage.update_campaign(app, campaign["id"],
                                    completed=campaign["completed"] + 1,
                                    participants=campaign["participants"] + 1,
                                    status="Completed" if campaign["status"] == "Draft"
                                    else campaign["status"])

    feedback = {"finished": finished, "points": points, "max_points": max_points,
                "details": details, "exercise": exercise,
                "total_score": quiz["score"], "total_max": quiz["max"]}
    # Re-assigning the key marks the session as modified so Flask sends the
    # updated cookie (mutating the nested dict alone would not do that).
    session["quiz"] = quiz
    return feedback, None if finished else exercise


@app.route("/learning")
def learning_page():
    """Learning centre: tips, safe/unsafe examples, link to the quiz."""
    tips = [
        ("Check the sender, not the display name",
         "Attackers set the display name to any company they like. Read the actual "
         "address after the @ sign and compare its domain with the official one."),
        ("Never share passwords, OTPs or card numbers by message",
         "No bank, college or company will ever ask you to reply with a password "
         "or a one-time code."),
        ("Type important addresses yourself",
         "Open a bookmark you created, or type the address manually, instead of "
         "clicking a link inside a suspicious message."),
        ("Slow down when there is a deadline",
         "‘Within 24 hours’, ‘account will be closed’, ‘final warning’ — pressure "
         "stops you thinking. Real organisations give you reasonable time."),
        ("Look at the registered domain",
         "In secure-paypal.login-check.top the real owner is login-check.top, "
         "not paypal. Read from right to left after the scheme."),
        ("Attachments need a reason",
         "Unexpected .zip/.exe files and ‘enable macros’ instructions are a classic "
         "malware delivery method."),
        ("Report instead of forwarding",
         "Forwarding a phishing message to friends spreads it. Report it to your "
         "mail provider and to the impersonated organisation."),
        ("Turn on two-factor authentication",
         "Even if a password leaks, 2FA stops the attacker from getting in."),
    ]
    safe_examples = [
        {"title": "College timetable notice",
         "text": "From: exams@tkiet.example.edu — The end-semester timetable has "
                 "been published on the college portal. No action is required from you.",
         "why": "Sent from the organisation's own domain, no link asking for a "
                "password, no deadline and no request for personal data."},
        {"title": "Newsletter you subscribed to",
         "text": "From: news@example.test — Here is this month's newsletter. You can "
                 "unsubscribe any time from the link at the bottom of the page.",
         "why": "Expected content, neutral tone and a working unsubscribe option."},
    ]
    unsafe_examples = [
        {"title": "Fake prize message",
         "text": "Congratulations! You have won a gift card. Pay the small processing "
                 "fee and share your UPI id to claim it now.",
         "why": "Too-good-to-be-true reward, an upfront fee and a request for payment "
                "details."},
        {"title": "Fake password reset",
         "text": "From: security@micros0ft-support.top — Your account will be closed "
                 "within 12 hours. Verify your password at the link below.",
         "why": "Lookalike sender domain, urgent threat, and a request to type a "
                "password after clicking a link."},
    ]
    return render_template("learning.html", tips=tips,
                           safe_examples=safe_examples, unsafe_examples=unsafe_examples,
                           categories=awareness_data.categories(),
                           exercises=awareness_data.get_exercises())


@app.route("/history", methods=["GET", "POST"])
def history_page():
    """Recent activity + option to clear demonstration records."""
    if request.method == "POST":
        mode = request.form.get("mode")
        if mode == "demo":
            deleted = storage.reset_demo_records(app)
            flash(f"{deleted} demonstration record(s) removed. Your own records were kept.",
                  "success")
        elif mode == "all":
            deleted = storage.reset_all_records(app)
            flash(f"{deleted} local record(s) cleared.", "success")
        else:
            flash("Unknown action.", "error")
        return redirect(url_for("history_page"))

    return render_template("history.html",
                           activity=storage.fetch_activity(app, limit=app.config["ACTIVITY_LIMIT"]),
                           analyses=storage.fetch_analyses(app, limit=25),
                           quizzes=storage.fetch_quiz_results(app, limit=25))


@app.route("/pricing")
def pricing_page():
    """Public pricing page (no account required)."""
    return render_template("pricing.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# JSON APIs (used by the JavaScript files)
# ---------------------------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    text, error = _clean_text(payload.get("message", ""), "message",
                              app.config["MAX_EMAIL_LENGTH"])
    if error:
        return jsonify(ok=False, error=error), 400

    try:
        rules_result = analyzer.analyze_message(text)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400

    ml_result = _run_ml(text)
    headline, engine, note = _combine(rules_result, ml_result)
    _record_analysis("email", text,
                     headline, rules_result["risk_score"],
                     [i["name"] for i in rules_result["indicators"]], engine)

    result = {"headline": headline, "engine": engine, "note": note,
              "rules": rules_result, "ml": ml_result}
    html = render_template("partials/_message_result.html", result=result)
    return jsonify(ok=True, headline=headline, engine=engine, note=note,
                   rules=rules_result, ml=ml_result, html=html)


@app.route("/api/url", methods=["POST"])
@app.route("/api/scan-url", methods=["POST"])
@limiter.limit("5 per minute")   # 5 requests / minute / IP — protects the URL-scanning budget
def api_url():
    payload = request.get_json(silent=True) or {}
    url, error = _clean_url(payload.get("url", ""))
    if error:
        return jsonify(ok=False, error=error), 400
    try:
        result = urlmod.analyze_url(url)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400

    _record_analysis("url", result["url"], result["classification"],
                     result["risk_score"], _risk_check_names(result), "rules")
    html = render_template("partials/_url_result.html", result=result)
    return jsonify(ok=True, result=result, html=html)


@app.route("/api/stats")
def api_stats():
    return jsonify(ok=True, stats=metrics.get_analytics(app))


@app.route("/api/model/status")
def api_model_status():
    return jsonify(ok=True, status=train_model.status(app.config["METRICS_PATH"],
                                                      app.config["MODEL_PATH"]))


@app.route("/api/train", methods=["POST"])
def api_train():
    """Train the TF-IDF + Naive Bayes model on the local fictional dataset."""
    try:
        result = train_model.train(app.config["DATASET_PATH"],
                                   app.config["MODEL_PATH"],
                                   app.config["VECTORIZER_PATH"],
                                   app.config["METRICS_PATH"],
                                   verbose=False)
    except train_model.TrainError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    return jsonify(ok=True, metrics=result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Local only: 127.0.0.1 means the app is not reachable from other machines.
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
