"""
desktop.py
----------
Windows desktop launcher for PhishLab AI.

Starts the Flask app on a background thread, then opens a native window
(pywebview / Edge WebView2 on Windows) pointing at it.

Run with:   python desktop.py
"""

import socket
import threading
import time
import webbrowser

from app import app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> None:
    port = _free_port()
    threading.Thread(
        target=lambda: app.run(
            host="127.0.0.1", port=port, debug=False, use_reloader=False
        ),
        daemon=True,
    ).start()

    if not _wait_ready(port):
        raise SystemExit("Flask server failed to start.")

    url = f"http://127.0.0.1:{port}"

    try:
        import webview
    except ImportError:
        webview = None

    if webview is not None:
        try:
            webview.create_window(
                "PhishLab AI",
                url,
                width=1280,
                height=800,
                min_size=(900, 600),
            )
            webview.start()
            return
        except Exception:
            # No desktop GUI available (headless Linux, missing GTK/Qt, …).
            # Fall through to the browser instead of crashing.
            pass

    webbrowser.open(url)
    print(f"PhishLab AI running at {url}  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
