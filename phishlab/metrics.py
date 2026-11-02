"""
phishlab/metrics.py
-------------------
Builds the statistics used by the Dashboard, Analytics and Reports pages.

Every number here is calculated from the local SQLite database, so the
charts always reflect what actually happened in this application.

Two record types are always kept apart:
    source = 'demo'  -> seeded demonstration data (presentation only)
    source = 'live'  -> real events produced by using the app
"""

import csv
import io
import json

from . import storage


def _count_by(rows, key):
    """Count how many times each value of `key` appears in a list of dicts."""
    out = {}
    for r in rows:
        value = r.get(key) or "(none)"
        out[value] = out.get(value, 0) + 1
    return out


def get_dashboard_stats(app):
    """Numbers for the dashboard cards and charts."""
    analyses = storage.fetch_analyses(app, limit=1000)
    quizzes = storage.fetch_quiz_results(app, limit=1000)
    campaigns = storage.list_campaigns(app)

    live_analyses = [a for a in analyses if a["source"] == "live"]
    demo_analyses = [a for a in analyses if a["source"] == "demo"]
    live_quizzes = [q for q in quizzes if q["source"] == "live"]
    demo_quizzes = [q for q in quizzes if q["source"] == "demo"]

    flagged = [a for a in analyses if a["classification"] in
               ("Potential phishing", "Elevated indicators — do not trust blindly")]
    review = [a for a in analyses if a["classification"] == "Needs review"]
    clean = [a for a in analyses if a["classification"] in
             ("No obvious indicators", "Few static indicators found")]

    completed_exercises = len(live_quizzes)
    quiz_correct = sum(1 for q in live_quizzes if q["correct"] == 1)
    quiz_pct = round(100 * quiz_correct / len(live_quizzes)) if live_quizzes else 0

    # Totals (live + seeded demo) — used by the outcome chart so the numbers
    # always match the rows actually stored in the database.
    demo_correct = sum(1 for q in demo_quizzes if q["correct"] == 1)
    quiz_answered_total = len(live_quizzes) + len(demo_quizzes)
    quiz_correct_total = quiz_correct + demo_correct
    quiz_incorrect_total = max(0, quiz_answered_total - quiz_correct_total)

    # Security-awareness score: a simple, explainable combination of
    # quiz accuracy and how many exercises were finished (max 10).
    accuracy_component = quiz_correct / max(1, len(live_quizzes)) if live_quizzes else 0
    progress_component = min(1.0, len(live_quizzes) / 10)
    awareness_score = round(100 * (0.7 * accuracy_component + 0.3 * progress_component)) \
        if live_quizzes else 0

    classification_counts = _count_by(analyses, "classification")
    engine_counts = _count_by(analyses, "engine")

    # Most frequent warning indicators (rule ids + url check names)
    indicator_counts = {}
    for a in analyses:
        try:
            names = json.loads(a["indicators"]) or []
        except (TypeError, ValueError):
            names = []
        for n in names:
            indicator_counts[n] = indicator_counts.get(n, 0) + 1

    common_indicators = sorted(indicator_counts.items(), key=lambda kv: -kv[1])[:8]

    campaign_completed = sum(c["completed"] for c in campaigns)
    campaign_participants = sum(c["participants"] for c in campaigns)
    campaign_completion_rate = (
        round(100 * campaign_completed / campaign_participants)
        if campaign_participants else 0
    )

    return {
        "total_analyses": len(analyses),
        "live_analyses": len(live_analyses),
        "demo_analyses": len(demo_analyses),
        "flagged": len(flagged),
        "needs_review": len(review),
        "clean": len(clean),
        "completed_exercises": completed_exercises,
        "quiz_accuracy": quiz_pct,
        "quiz_answered_live": len(live_quizzes),
        "quiz_answered_demo": len(demo_quizzes),
        "quiz_correct": quiz_correct,
        "quiz_answered_total": quiz_answered_total,
        "quiz_correct_total": quiz_correct_total,
        "quiz_incorrect_total": quiz_incorrect_total,
        "awareness_score": awareness_score,
        "classification_counts": classification_counts,
        "engine_counts": engine_counts,
        "common_indicators": [{"name": n, "count": c} for n, c in common_indicators],
        "campaigns_total": len(campaigns),
        "campaign_completion_rate": campaign_completion_rate,
        "campaign_participants": campaign_participants,
        "has_live_data": bool(live_analyses or live_quizzes),
    }


def get_analytics(app):
    """Richer statistics for the Analytics & Reports page."""
    stats = get_dashboard_stats(app)
    analyses = storage.fetch_analyses(app, limit=1000)
    quizzes = storage.fetch_quiz_results(app, limit=1000)

    # Per-day counts for the activity trend (last 7 days labels)
    day_counts = {}
    for a in analyses:
        day = (a["created_at"] or "")[:10]
        day_counts[day] = day_counts.get(day, 0) + 1
    trend = sorted(day_counts.items())[-7:]

    # Correct identification rate for exercises where the model/rules
    # and the human were both involved: quiz accuracy is the human side.
    correct_rate = stats["quiz_accuracy"]

    email_rows = [a for a in analyses if a["kind"] == "email"]
    url_rows = [a for a in analyses if a["kind"] == "url"]

    avg_email = round(sum(a["risk_score"] for a in email_rows) / len(email_rows)) if email_rows else 0
    avg_url = round(sum(a["risk_score"] for a in url_rows) / len(url_rows)) if url_rows else 0

    return {
        **stats,
        "trend_labels": [t[0] for t in trend],
        "trend_values": [t[1] for t in trend],
        "email_count": len(email_rows),
        "url_count": len(url_rows),
        "avg_email_score": avg_email,
        "avg_url_score": avg_url,
        "correct_identification_rate": correct_rate,
        "quiz_total": len(quizzes),
        "recent_analyses": analyses[:15],
        "recent_quizzes": quizzes[:15],
    }


def _escape_excel(value):
    """Stop CSV cells from being interpreted as formulas by spreadsheet apps."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def build_csv_report(app):
    """
    Create a CSV report of non-sensitive local statistics.
    Contains counts, scores and timestamps — never message bodies,
    passwords or personal details.
    """
    stats = get_analytics(app)
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow(["PhishLab AI — Local Statistics Report"])
    writer.writerow(["Generated at", storage.now()])
    writer.writerow(["Note", "Educational project data stored on this computer only."])
    writer.writerow([])

    writer.writerow(["Metric", "Value"])
    for label, key in [
        ("Total analyses recorded", "total_analyses"),
        ("Analyses by you (live)", "live_analyses"),
        ("Seeded demonstration analyses", "demo_analyses"),
        ("Flagged as potential phishing", "flagged"),
        ("Marked as needs review", "needs_review"),
        ("No obvious indicators", "clean"),
        ("Awareness exercises completed (live)", "completed_exercises"),
        ("Quiz accuracy % (live)", "quiz_accuracy"),
        ("Awareness score (0-100)", "awareness_score"),
        ("Correct identification rate %", "correct_identification_rate"),
        ("Campaigns", "campaigns_total"),
        ("Campaign completion rate %", "campaign_completion_rate"),
        ("Average email risk score", "avg_email_score"),
        ("Average URL risk score", "avg_url_score"),
    ]:
        writer.writerow([label, stats.get(key, "")])

    writer.writerow([])
    writer.writerow(["Classification", "Count"])
    for name, count in (stats.get("classification_counts") or {}).items():
        writer.writerow([_escape_excel(name), count])

    writer.writerow([])
    writer.writerow(["Common warning indicator", "Occurrences"])
    for item in stats.get("common_indicators", []):
        writer.writerow([_escape_excel(item["name"]), item["count"]])

    writer.writerow([])
    writer.writerow(["Recent event", "Type", "Result", "Time", "Source"])
    for row in storage.fetch_activity(app, limit=30):
        writer.writerow([
            _escape_excel(row["ref"]), _escape_excel(row["type"]),
            _escape_excel(row["result"]), row["created_at"], row["source"],
        ])

    return buffer.getvalue()
