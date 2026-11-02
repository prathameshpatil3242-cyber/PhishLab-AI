# PHISHLAB AI

**AI-Powered Phishing Detection, Simulation and Awareness System**

An educational cybersecurity web application built for an SY B.Tech Cyber
Security student at **TKIET Warananagar, Maharashtra, India**.

PhishLab AI:

- analyses email text and URLs for phishing warning signs (explainable rules),
- classifies sample messages with a small machine-learning model (TF-IDF +
  Multinomial Naive Bayes),
- explains *why* a message may be suspicious,
- runs safe, opt-in phishing-awareness quizzes with fictional scenarios,
- shows security-awareness analytics on a dark-themed dashboard,
- stores optional demonstration activity locally in SQLite.

> **Safety first.** Only fictional messages, synthetic participants and
> `.test` / `.example` domains are used. The application **never** sends
> phishing emails, never collects credentials, never opens submitted URLs and
> never transmits data anywhere outside your computer.

---

## 1. What you need

| Item | Notes |
|------|-------|
| **Python 3.13** (or 3.10+) | Check with `python --version` |
| **Windows 10/11** with PowerShell | Commands below are for PowerShell |
| ~500 MB free disk space | For Python packages and the model |
| A modern browser | Chrome, Edge or Firefox |

No paid services, no API keys and no internet connection are required after the
packages are installed.

---

## 2. Setup — step by step (Windows PowerShell)

Open **PowerShell**, then run these commands **inside the project folder**:

```powershell
# 1. Go to the project folder (adjust the path if needed)
cd C:\path\to\PhishLab-AI

# 2. One-shot deploy (venv + packages + model + database)
powershell -ExecutionPolicy Bypass -File deploy_windows.ps1
```

Then start the app however you like:

| How | Command |
|-----|---------|
| **Desktop window** (recommended) | `.\desktop.bat` |
| **Dev browser tab** | `.\start.bat` |
| **Production server** | `.\start_prod.bat` |
| **Standalone .exe** | Run `build_windows.bat` once, then double-click `dist\PhishLabAI.exe` |

For the standalone Windows application:

```powershell
# One-time build → produces dist\PhishLabAI.exe
.\build_windows.bat
```

Copy **one file** (`dist\PhishLabAI.exe`) to any Windows 10/11 machine — no
Python install required — and double-click it. The app opens in a native
window and stores its database under `%LOCALAPPDATA%\PhishLabAI`.

---

## 3. Everyday commands

| Task | Command (with the venv activated) |
|------|-----------------------------------|
| Start the app | `python app.py` |
| Train / re-train the model | `python train_model.py` |
| Re-check the saved model on held-out data | `python evaluate_model.py` |
| Show database row counts | `python database.py info` |
| Remove seeded demo records | `python database.py clear` |
| Delete **all** local records | `python database.py reset` |
| Run the tests | `python -m pytest tests/ -q` |

Deactivate the virtual environment when you are done:

```powershell
deactivate
```

---

## 4. Pages you can open

| Menu item | What it does |
|-----------|--------------|
| **Dashboard** | KPI cards, awareness score, charts, recent activity, model status |
| **Analyze Message** | Paste a message → rule indicators + ML prediction + advice |
| **URL Analyzer** | Inspect a URL *as text only* (it is never visited) |
| **Awareness Campaigns** | Local fictional campaigns; “Start quiz” opens the local quiz |
| **Quiz & Learning Centre** | Tips, safe/unsafe examples and the 10-question interactive quiz |
| **Recent Activity** | Stored analyses, quiz events; buttons to clear demo/all records |
| **About Project** | What the project is, safety rules and honest limitations |

Every visible button performs a real action — there are no decorative controls.

---

## 5. Project structure

```
PhishLab-AI/
├── app.py               Flask app: all routes, APIs, CSRF protection
├── config.py            Paths, input limits, secret-key handling
├── database.py          CLI helper: init / clear / reset / info
├── train_model.py       Trains TF-IDF + Naive Bayes, prints real metrics
├── evaluate_model.py    Re-scores the saved model on held-out data
├── requirements.txt     Python packages
├── data/
│   ├── sample_messages.csv   100 fictional labelled messages
│   └── make_dataset.py       Script that generated the CSV
├── models/              model.joblib, vectorizer.joblib, metrics.json
├── phishlab/
│   ├── analyzer.py      Rule-based message analysis (explainable)
│   ├── url_analyzer.py  Static URL checks (never visits the URL)
│   ├── train_model.py   The ML pipeline module
│   ├── metrics.py       Dashboard statistics from SQLite
│   ├── storage.py       All SQLite operations (parameterised SQL)
│   └── awareness_data.py  10 fictional quiz exercises + grading
├── templates/           Jinja2 HTML pages + partials
├── static/
│   ├── css/style.css    Dark navy/violet/lime dashboard theme
│   └── js/              app.js, dashboard.js, analyzer.js, Chart.js
└── tests/               pytest suite (79 tests)
```

---

## 6. How the pieces fit together

```
Browser  ──HTML/JS──►  Flask (app.py)
                          │
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
  analyzer.py        train_model.py      storage.py
  (rules, scores)    (TF-IDF + NB)       (SQLite file)
        │                 │                  │
        └────────► metrics.py ◄──────────────┘
                   (dashboard numbers)
```

1. You submit a form or a JavaScript `fetch()` call.
2. Flask validates the input (length, format, CSRF token).
3. The **rule engine** checks the text against ~14 explainable rules and adds
   up their weights (0–100 heuristic score).
4. If a model has been trained, the **ML pipeline** predicts `phishing` or
   `legitimate` and returns class probabilities.
5. The two results are shown **separately** and combined into one headline
   label using a documented decision table (see `app.py::_combine`).
6. A short **redacted** snippet and the score are stored in SQLite for the
   dashboard and Recent Activity pages.

---

## 7. Testing

```powershell
python -m pytest tests/ -q
```

The suite covers ordinary and suspicious fictional messages, empty and
oversized input, malformed URLs, missing model files, invalid form
submissions, dashboard and analysis routes, quiz submission, campaign CRUD,
database clearing, CSRF protection, XSS escaping and ML training on a
temporary folder. Tests never contact the network.

---

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
| `'python' is not recognized` | Install Python 3.13 from python.org and tick **“Add python.exe to PATH”**. |
| `python -m venv` fails | Install the official Python, not the Microsoft Store stub. |
| PowerShell refuses `Activate.ps1` | Run `Set-ExecutionPolicy -Scope Process RemoteSigned` once, then re-activate. |
| `No module named 'flask'` | The venv is not activated — run `.venv\Scripts\Activate.ps1` again, then `pip install -r requirements.txt`. |
| Dashboard says **“ML model not trained”** | Run `python train_model.py` (or press **Train model now** on the dashboard). The app still works with the rule engine alone. |
| Port 5000 already in use | Edit the last line of `app.py` to use port 5001, or close the other program. |
| `database.py` errors | Run `python database.py init` once, then start the app. |
| Tests fail after manual experiments | Delete `test_phishlab.db` — it is recreated automatically. |
| Want a clean slate | `python database.py reset` then restart the app. |

---

## 9. Honest limitations

- The dataset is **small and fictional**. The reported accuracy describes
  held-out fictional rows only — it does **not** predict real-world
  detection quality.
- Rule scores and ML probabilities are **educational heuristics**. They are
  not validated probabilities that an attack is happening.
- “No obvious phishing indicators” never means a message is **safe**.
- Modern phishing can avoid every keyword rule. Always verify through the
  official app or website of the organisation mentioned.

## 10. Ideas for future work

- Add a larger, public research dataset and compare several classifiers.
- Extract link/text mismatch automatically from HTML-formatted mail.
- Add a simple staff-vs-student campaign leaderboard (local only).
- Package the app with Docker for lab machines.
- Add unit tests for every individual rule and URL check.

---

*Built for learning. Runs 100 % on your own machine.*
