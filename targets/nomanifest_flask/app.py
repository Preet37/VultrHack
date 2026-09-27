"""A small, REAL Flask app that ships NO manifest.json.

Unlike targets/seeded_flask, this app plants no canaries of its own and declares
nothing about its bugs. It is here to prove the finder can confirm exploits on a
target it knows nothing about ahead of time -- using ENVIRONMENTAL canaries that
Cerberus plants in the sandbox around the app (see finder/env_canary.py), not
canaries planted in this repo.

It has two genuine, app-agnostic bugs:
  - path traversal on GET /download?file=...  (user input joined to a base dir
    and read with no sanitization -- an absolute or ``../`` path escapes it)
  - SSRF on GET /fetch?url=...  (the server fetches a user-supplied URL with no
    scheme/host allowlist and no block on internal targets)

DELIBERATELY vulnerable. Never deploy. It runs the same way the seeded targets
do (LocalSubprocessRunner: `python app.py`, honoring $PORT, serving /health).
"""

import os
import urllib.request
from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)

# The document root the /download route is *supposed* to serve from. The
# environmental sentinel Cerberus plants lives OUTSIDE this directory, so only a
# real traversal can reach it.
DOCS = Path(__file__).with_name("docs")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    # Link the vulnerable routes so a manifest-less recon crawl discovers them.
    return Response(
        "<h1>Team Notes</h1>"
        '<p>Docs: <a href="/download?file=welcome.txt">welcome</a></p>'
        '<p>Link preview: <a href="/fetch?url=/">preview</a></p>',
        mimetype="text/html",
    )


@app.get("/download")
def download():
    # VULNERABLE (path traversal): the file name is joined to DOCS with no
    # sanitization, so an absolute path or ../ escape reads anything readable.
    name = request.args.get("file", "")
    target = DOCS / name
    try:
        data = Path(target).read_bytes()
    except (OSError, ValueError):
        return Response("not found", status=404, mimetype="text/plain")
    return Response(data, mimetype="application/octet-stream")


@app.get("/fetch")
def fetch():
    # VULNERABLE (SSRF): fetches whatever URL the caller supplies, with no
    # allowlist and no block on loopback/internal addresses.
    url = request.args.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 (planted bug)
            body = resp.read(4096)
    except (ValueError, OSError):
        return Response("fetch failed", status=502, mimetype="text/plain")
    return Response(body, mimetype="application/octet-stream")


def create_app():
    DOCS.mkdir(exist_ok=True)
    (DOCS / "welcome.txt").write_text("Welcome to Team Notes.\n")
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", "5002"))
    app.run(host="127.0.0.1", port=port)
