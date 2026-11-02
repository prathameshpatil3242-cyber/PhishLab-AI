#!/usr/bin/env python3
"""
database.py
-----------
Small command-line helper for the local SQLite database.

    python database.py init      create tables + seed demonstration records
    python database.py clear     delete demonstration records (keep yours)
    python database.py reset     delete every record
    python database.py info      show row counts

The Flask application also creates the tables automatically the first time
it starts, so running `init` is optional — it is useful if you want demo
data in place before opening the browser.
"""

import sys

import config
from app import app as flask_app
from phishlab import storage


def _run(fn, *args):
    """Run a storage helper inside a Flask application context."""
    with flask_app.app_context():
        return fn(flask_app, *args)


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 1

    command = argv[1].lower()

    if command == "init":
        storage.init_db(flask_app)
        print(f"Database ready: {config.Config.DATABASE_PATH}")
        return 0

    if command == "clear":
        storage.init_db(flask_app)
        deleted = _run(storage.reset_demo_records)
        print(f"Removed {deleted} demonstration record(s).")
        return 0

    if command == "reset":
        storage.init_db(flask_app)
        deleted = _run(storage.reset_all_records)
        print(f"Removed {deleted} record(s).")
        return 0

    if command == "info":
        storage.init_db(flask_app)
        conn = storage.connect(config.Config.DATABASE_PATH)
        try:
            for table in ("analyses", "quiz_results", "campaigns", "activity"):
                row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
                print(f"  {table:<14} {row['c']} row(s)")
        finally:
            conn.close()
        return 0

    print(f"Unknown command: {command}. Use init | clear | reset | info")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
