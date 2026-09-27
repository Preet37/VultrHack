"""Clean Flask app for the Cerberus finder — the SAFE counterpart to seeded_flask.

Same routes and the same armed canaries, but every handler is written correctly:
parameterized SQL, path validation, no shell, an SSRF allowlist, and an ownership
check. The finder arms its canaries and fires every class at every sink — and no
canary ever leaves the box. So the finder proves this target CLEAN, the honest way
(it tested and nothing leaked), not merely "we couldn't find anything".

Never a planted bug here. It runs only inside a throwaway sandbox like any target.
"""

import ipaddress
import os
import socket
import sqlite3
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, request

CANARY = os.environ.get("CERBERUS_CANARY", "CANARY-a1b2c3d4e5f60718-DO-NOT-EXFIL")
FILE_CANARY = os.environ.get("CERBERUS_FILE_CANARY", "FILECANARY-9f8e7d6c5b4a-DO-NOT-READ")
ACCT_CANARY = os.environ.get("CERBERUS_ACCT_CANARY", "ACCTCANARY-1a2b3c4d5e6f-DO-NOT-SHARE")
SSRF_CANARY = os.environ.get("CERBERUS_SSRF_CANARY", "SSRFCANARY-0f1e2d3c4b5a-INTERNAL-ONLY")
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
    cur.execute("CREATE TABLE secrets (id INTEGER PRIMARY KEY, label TEXT, value TEXT)")
    cur.execute("INSERT INTO secrets (id, label, value) VALUES (1, 'admin_api_token', ?)", (CANARY,))
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
    # SAFE: bound as a parameter — input can never change the SQL structure.
    product_id = request.args.get("id", "")
    conn = get_db()
    try:
        rows = conn.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,)).fetchall()
    except sqlite3.Error as exc:
        return Response(f"query error: {exc}", status=500, mimetype="text/plain")
    finally:
        conn.close()
    if not rows:
        return Response("no such product", status=404, mimetype="text/plain")
    return Response("\n".join(f"{r[0]} | {r[1]} | ${r[2]}" for r in rows), mimetype="text/plain")


@app.get("/download")
def download():
    # SAFE: reject separators/absolute paths and confirm the resolved path stays under docs/.
    name = request.args.get("file", "")
    base = Path(__file__).with_name("docs").resolve()
    if ".." in name or Path(name).is_absolute():
        return Response("forbidden", status=403, mimetype="text/plain")
    target = (base / name).resolve()
    if not str(target).startswith(str(base) + os.sep):
        return Response("forbidden", status=403, mimetype="text/plain")
    try:
        return Response(target.read_bytes(), mimetype="application/octet-stream")
    except (OSError, ValueError):
        return Response("not found", status=404, mimetype="text/plain")


@app.get("/net")
def net():
    # SAFE: argument list with the shell off — input is data, never shell syntax.
    host = request.args.get("host", "")
    result = subprocess.run(
        ["echo", host], shell=False, capture_output=True, text=True, cwd=str(Path(__file__).parent)
    )
    return Response(result.stdout + result.stderr, mimetype="text/plain")


@app.get("/internal/metadata")
def internal_metadata():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return Response("forbidden", status=403, mimetype="text/plain")
    return Response(f"instance-credential: {SSRF_CANARY}", mimetype="text/plain")


def _is_internal(host: str) -> bool:
    try:
        for res in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(res[4][0])
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved:
                return True
    except (socket.gaierror, ValueError):
        return True  # unresolvable -> refuse
    return False


@app.get("/fetch")
def fetch():
    # SAFE: allowlist scheme, resolve the host, block loopback/private/internal targets.
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or _is_internal(parsed.hostname):
        return Response("forbidden", status=403, mimetype="text/plain")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = resp.read(4096)
    except (ValueError, OSError):
        return Response("fetch failed", status=502, mimetype="text/plain")
    return Response(body, mimetype="application/octet-stream")


@app.get("/account")
def account():
    # SAFE: the caller may only read the account they own.
    current_user = SESSION_USER
    account_id = request.args.get("id", current_user)
    if str(account_id) != str(current_user):
        return Response("forbidden", status=403, mimetype="text/plain")
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
    Path(__file__).with_name("app_secret.txt").write_text(
        f"internal service credential: {FILE_CANARY}\n"
    )
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="127.0.0.1", port=port)
