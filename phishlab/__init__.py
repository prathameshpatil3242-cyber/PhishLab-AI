"""
phishlab package
----------------
PhishLab AI is organised as a small Python package so that each part of the
system has its own file:

    analyzer.py      -> rule-based email/message analysis (explainable)
    url_analyzer.py  -> static URL character analysis (never visits URLs)
    train_model.py   -> machine-learning training pipeline (TF-IDF + Naive Bayes)
    metrics.py       -> statistics used by the dashboard/analytics pages
    storage.py       -> SQLite helpers (local database)
    awareness_data.py-> fictional quiz exercises
"""

__version__ = "1.0.0"
