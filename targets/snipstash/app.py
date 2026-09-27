"""Seeded vulnerable Flask app #2: "SnipStash", a code-snippet service.

DELIBERATELY vulnerable, like targets/seeded_flask, but a DIFFERENT codebase --
different domain, route names, parameters, table names, and bug placement. Its
purpose is to prove the finder adapts to an app it was not shaped around, rather
than being hardcoded to one target. Never deploy this; it runs only in a
throwaway sandbox.

Planted bugs (authoritative list in manifest.json):
  - SQL injection on GET /snippet?id=...     (concatenated query; canary in `vault`)
  - Path traversal on GET /raw?path=...       (unsanitized join under pastes/)
  - Command injection on GET /diag?target=... (shell=True)
  - SSRF on GET /preview?src=...              (urlopen of an attacker URL)
  - Auth bypass / IDOR on GET /note?id=...    (no ownership check)

Canary strings are DIFFERENT from app #1, and the SQLi canary lives in a table
named `vault` (not `secrets`) so the generic SQLite exfiltration confirmer must
discover it, not assume a table name.
"""

import os
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from flask import Flask, Response, request

DB_CANARY = os.environ.get("CERBERUS_CANARY", "VAULTCANARY-11223344aabbccdd-DO-NOT-EXFIL")
FILE_CANARY = os.environ.get("CERBERUS_FILE_CANARY", "FILECANARY-snip-556677-DO-NOT-READ")
NOTE_CANARY = os.environ.get("CERBERUS_NOTE_CANARY", "NOTECANARY-99887766-PRIVATE")
SSRF_CANARY = os.environ.get("CERBERUS_SSRF_CANARY", "SSRFCANARY-snip-abcdef-INTERNAL")
# Server-side authenticated user for this demo session (never client-supplied).
SESSION_USER = "1"

DB_PATH = Path(__file__).with_name("snip.db")

app = Flask(__name__)


def init_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE snippets (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    cur.executemany(
        "INSERT INTO snippets (id, title, body) VALUES (?, ?, ?)",
        [(1, "hello", "print('hi')"), (2, "loop", "for i in range(3): pass"), (3, "http", "requests.get(url)")],
    )
    # SQLi canary in a table named `vault` -- no route selects it legitimately.
    cur.execute("CREATE TABLE vault (id INTEGER PRIMARY KEY, name TEXT, token TEXT)")
    cur.execute("INSERT INTO vault (id, name, token) VALUES (1, 'deploy_key', ?)", (DB_CANARY,))
    # Notes for the IDOR demo: user 1 owns note 1; note 2's body is the canary.
    cur.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    cur.executemany(
        "INSERT INTO notes (id, owner, body) VALUES (?, ?, ?)",
        [(1, "you", "remember the milk"), (2, "ceo", NOTE_CANARY)],
    )
    conn.commit()
    conn.close()


def get_db():
    return sqlite3.connect(DB_PATH)


@app.get("/")
def index():
    return Response("<h1>SnipStash</h1><p>Paste and share code snippets.</p>", mimetype="text/html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/snippet")
def snippet():
    # VULNERABLE (SQLi): id concatenated into the query.
    snippet_id = request.args.get("id", "")
    query = "SELECT id, title, body FROM snippets WHERE id = " + snippet_id  # planted bug
    conn = get_db()
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        return Response(f"query error: {exc}", status=500, mimetype="text/plain")
    finally:
        conn.close()
    if not rows:
        return Response("no such snippet", status=404, mimetype="text/plain")
    return Response("\n".join(f"{r[0]} | {r[1]} | {r[2]}" for r in rows), mimetype="text/plain")


@app.get("/raw")
def raw():
    # VULNERABLE (path traversal): path joined under pastes/ without checks.
    path = request.args.get("path", "")
    base = Path(__file__).with_name("pastes")
    target = base / path  # planted bug
    try:
        data = Path(target).read_bytes()
    except (OSError, ValueError):
        return Response("not found", status=404, mimetype="text/plain")
    return Response(data, mimetype="application/octet-stream")


@app.get("/diag")
def diag():
    # VULNERABLE (command injection): target interpolated into a shell command.
    target = request.args.get("target", "")
    result = subprocess.run(  # planted bug
        "echo " + target, shell=True, capture_output=True, text=True, cwd=str(Path(__file__).parent)
    )
    return Response(result.stdout + result.stderr, mimetype="text/plain")


@app.get("/internal/metadata")
def internal_metadata():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return Response("forbidden", status=403, mimetype="text/plain")
    return Response(f"deploy-credential: {SSRF_CANARY}", mimetype="text/plain")


@app.get("/preview")
def preview():
    # VULNERABLE (SSRF): fetches an attacker-supplied URL with no validation.
    src = request.args.get("src", "")
    try:
        with urllib.request.urlopen(src, timeout=5) as resp:  # planted bug
            body = resp.read(4096)
    except (ValueError, OSError):
        return Response("preview failed", status=502, mimetype="text/plain")
    return Response(body, mimetype="application/octet-stream")


@app.get("/note")
def note():
    # VULNERABLE (auth bypass / IDOR): returns any note by id, no ownership check.
    current_user = SESSION_USER  # server-trusted identity, not client-supplied
    note_id = request.args.get("id", current_user)
    conn = get_db()
    try:
        row = conn.execute("SELECT owner, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return Response("no such note", status=404, mimetype="text/plain")
    return Response(f"{row[0]}: {row[1]}", mimetype="text/plain")


def create_app():
    init_db()
    pastes = Path(__file__).with_name("pastes")
    pastes.mkdir(exist_ok=True)
    (pastes / "welcome.txt").write_text("Welcome to SnipStash.\n")
    # Planted secret OUTSIDE pastes/ -- only a ../ traversal or a shell command
    # running in the app dir can read it.
    Path(__file__).with_name("app_secret.txt").write_text(f"deploy secret: {FILE_CANARY}\n")
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", "5002"))
    app.run(host="127.0.0.1", port=port)
