"""Seeded vulnerable Flask app for the Cerberus finder.

This app is DELIBERATELY vulnerable. It exists so the finder has a target with
known, planted bugs and a known canary, so the exploit and patch stages fire
reliably in a demo. Never deploy this. It runs only inside a throwaway sandbox.

Planted bugs (see manifest.json for the authoritative list):
  - SQL injection on GET /product?id=...   (string-concatenated query)
  - Path traversal on GET /download?file=... (unsanitized join + open)

The canary is a fake credential stored in a `secrets` table that no legitimate
route ever selects. If the canary string leaves the box, only an exploit could
have carried it out -> the environment, not the model, confirms the finding.
"""

import os
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from flask import Flask, Response, request

# A fixed, known canary. The finder's oracle checks for this exact string.
# In the real system this is planted per-run; here it is fixed for the demo.
CANARY = os.environ.get("CERBERUS_CANARY", "CANARY-a1b2c3d4e5f60718-DO-NOT-EXFIL")
# A second canary planted in a FILE that sits outside the served docs/ dir. Only a
# path-traversal escape can read it, so its appearance proves the traversal fired.
FILE_CANARY = os.environ.get("CERBERUS_FILE_CANARY", "FILECANARY-9f8e7d6c5b4a-DO-NOT-READ")
# Canary held by ANOTHER user's account; only a missing ownership check (IDOR)
# lets the logged-in user read it.
ACCT_CANARY = os.environ.get("CERBERUS_ACCT_CANARY", "ACCTCANARY-1a2b3c4d5e6f-DO-NOT-SHARE")
# Canary served only by an internal-only endpoint; only an SSRF that makes the
# server fetch that endpoint can carry it back out.
SSRF_CANARY = os.environ.get("CERBERUS_SSRF_CANARY", "SSRFCANARY-0f1e2d3c4b5a-INTERNAL-ONLY")
# The authenticated user for this demo session. Server-side and trusted -- NOT
# derived from any client-supplied value.
SESSION_USER = "1"

DB_PATH = Path(__file__).with_name("shop.db")

app = Flask(__name__)


def init_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT)")
    cur.executemany(
        "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
        [(1, "Wireless Mouse", "24.99"), (2, "Mechanical Keyboard", "89.00"), (3, "USB-C Hub", "39.50")],
    )
    # The canary lives in a table the product route never touches. Only an
    # injection that breaks out of the intended query can reach it.
    cur.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, label TEXT, value TEXT)")
    cur.execute("INSERT INTO secrets (id, label, value) VALUES (1, 'admin_api_token', ?)", (CANARY,))
    # Accounts for the IDOR demo: user 1 is "you"; user 2's secret is the canary.
    cur.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT, secret TEXT)")
    cur.executemany(
        "INSERT INTO accounts (id, owner, secret) VALUES (?, ?, ?)",
        [(1, "you", "your-own-token"), (2, "admin", ACCT_CANARY)],
    )
    conn.commit()
    conn.close()


def get_db():
    return sqlite3.connect(DB_PATH)


@app.get("/")
def index():
    return Response(
        "<h1>Demo Shop</h1><ul>"
        '<li><a href="/product?id=1">Wireless Mouse</a></li>'
        '<li><a href="/product?id=2">Mechanical Keyboard</a></li>'
        '<li><a href="/product?id=3">USB-C Hub</a></li>'
        "</ul>"
        '<p>Docs: <a href="/download?file=readme.txt">readme</a></p>',
        mimetype="text/html",
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/product")
def product():
    # VULNERABLE (SQLi): the id is concatenated straight into the SQL string.
    # Correct fix: parameterized query -> "SELECT ... WHERE id = ?", (id,)
    product_id = request.args.get("id", "")
    query = "SELECT id, name, price FROM products WHERE id = " + product_id  # noqa: S608 (planted bug)
    conn = get_db()
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        return Response(f"query error: {exc}", status=500, mimetype="text/plain")
    finally:
        conn.close()
    if not rows:
        return Response("no such product", status=404, mimetype="text/plain")
    body = "\n".join(f"{r[0]} | {r[1]} | ${r[2]}" for r in rows)
    return Response(body, mimetype="text/plain")


@app.get("/download")
def download():
    # VULNERABLE (path traversal): file name is joined without sanitization.
    # Correct fix: reject separators / resolve and confirm the path stays under base.
    name = request.args.get("file", "")
    base = Path(__file__).with_name("docs")
    target = base / name  # planted bug: allows ../ escape
    try:
        data = Path(target).read_bytes()
    except (OSError, ValueError):
        return Response("not found", status=404, mimetype="text/plain")
    return Response(data, mimetype="application/octet-stream")


@app.get("/net")
def net():
    # VULNERABLE (command injection): the host is interpolated into a shell string.
    # Correct fix: pass an argument list with shell=False, no shell metacharacters.
    host = request.args.get("host", "")
    result = subprocess.run(  # planted bug
        "echo " + host, shell=True, capture_output=True, text=True, cwd=str(Path(__file__).parent)
    )
    return Response(result.stdout + result.stderr, mimetype="text/plain")


@app.get("/internal/metadata")
def internal_metadata():
    # Intended to be reachable only from inside the network. Returns a secret.
    # Reachable from the public /fetch route via SSRF.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return Response("forbidden", status=403, mimetype="text/plain")
    return Response(f"instance-credential: {SSRF_CANARY}", mimetype="text/plain")


@app.get("/fetch")
def fetch():
    # VULNERABLE (SSRF): the server fetches an attacker-supplied URL with no
    # validation. Correct fix: allowlist scheme/host and block internal targets.
    url = request.args.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # planted bug
            body = resp.read(4096)
    except (ValueError, OSError):
        return Response("fetch failed", status=502, mimetype="text/plain")
    return Response(body, mimetype="application/octet-stream")


@app.get("/account")
def account():
    # VULNERABLE (auth bypass / IDOR): returns any account by id without checking
    # the logged-in user owns it. Correct fix: enforce the caller owns the object.
    current_user = SESSION_USER  # server-trusted identity, not client-supplied
    account_id = request.args.get("id", current_user)
    conn = get_db()
    try:
        row = conn.execute("SELECT owner, secret FROM accounts WHERE id = ?", (account_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return Response("no such account", status=404, mimetype="text/plain")
    return Response(f"{row[0]}: {row[1]}", mimetype="text/plain")


def create_app():
    init_db()
    docs = Path(__file__).with_name("docs")
    docs.mkdir(exist_ok=True)
    (docs / "readme.txt").write_text("Public documentation for the demo shop.\n")
    # Planted secret OUTSIDE docs/ (sibling of app.py). The /download route serves
    # from docs/, so this file is only reachable via a ../ traversal escape.
    Path(__file__).with_name("app_secret.txt").write_text(
        f"internal service credential: {FILE_CANARY}\n"
    )
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="127.0.0.1", port=port)
