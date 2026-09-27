"""TicketFlow — a tiny Flask helpdesk.

A minimal support-ticket app: list tickets, download attachments, preview linked
URLs, and run a quick network diagnostic. Single-file, SQLite, no build step.

    pip install -r requirements.txt
    python app.py        # serves on http://127.0.0.1:5001 (or $PORT)

Not production-hardened — this is a demo app.
"""

import os
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from flask import Flask, Response, request

BASE = Path(__file__).parent
UPLOADS = BASE / "uploads"
DB_PATH = BASE / "tickets.db"

app = Flask(__name__)


def init_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, subject TEXT, status TEXT)")
    conn.executemany(
        "INSERT INTO tickets (id, subject, status) VALUES (?, ?, ?)",
        [(1, "Cannot reset my password", "open"),
         (2, "Invoice #4021 looks wrong", "pending"),
         (3, "Feature request: dark mode", "closed")],
    )
    conn.commit()
    conn.close()


@app.get("/")
def index():
    return Response(
        "<h1>TicketFlow</h1>"
        "<p>Internal support desk.</p>"
        "<ul>"
        '<li><a href="/tickets">All tickets</a></li>'
        '<li><a href="/attachments?file=welcome.txt">Download attachment</a></li>'
        '<li><a href="/link-preview?url=https://example.com">Preview a link</a></li>'
        '<li><a href="/tools/ping?host=8.8.8.8">Network diagnostics</a></li>'
        "</ul>",
        mimetype="text/html",
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/tickets")
def tickets():
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute("SELECT id, subject, status FROM tickets").fetchall()
    finally:
        conn.close()
    body = "\n".join(f"#{r[0]} [{r[2]}] {r[1]}" for r in rows)
    return Response(body, mimetype="text/plain")


@app.get("/attachments")
def attachments():
    # Serve a customer-uploaded attachment by name.
    name = request.args.get("file", "welcome.txt")
    path = os.path.join(str(UPLOADS), name)  # no sanitization
    try:
        with open(path, "rb") as fh:
            return Response(fh.read(), mimetype="application/octet-stream")
    except OSError:
        return Response("attachment not found", status=404, mimetype="text/plain")


@app.get("/link-preview")
def link_preview():
    # Fetch the target URL so agents can preview links pasted into a ticket.
    url = request.args.get("url", "")
    if not url:
        return Response("provide ?url=", status=400, mimetype="text/plain")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # no allowlist
            return Response(resp.read(4096), mimetype="application/octet-stream")
    except (ValueError, OSError):
        return Response("could not fetch", status=502, mimetype="text/plain")


@app.get("/tools/ping")
def ping():
    # Quick reachability check for an agent debugging a customer's host.
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(
        "ping -c 1 " + host, shell=True, capture_output=True, text=True, timeout=8
    )  # host is interpolated into a shell string
    return Response(out.stdout + out.stderr, mimetype="text/plain")


def create_app():
    init_db()
    UPLOADS.mkdir(exist_ok=True)
    (UPLOADS / "welcome.txt").write_text("Welcome to TicketFlow. Attach files to your tickets here.\n")
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="127.0.0.1", port=port)
