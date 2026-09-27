"""Recon: build the attack-surface map (routes, inputs, dependencies).

Two sources, merged:
  1. A `manifest.json` beside the target source, if present. Authoritative for
     seeded targets where we control the exact route/param/canary.
  2. A light HTTP crawl of the running app: fetch a few known/linked pages and
     extract links and query parameters. Lets the finder work on a target that
     ships no manifest.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from finder.models import Route

_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_DEFAULT_CANARY = "CANARY-a1b2c3d4e5f60718-DO-NOT-EXFIL"


def canaries_for(manifest: dict | None) -> list[str]:
    """All planted canaries whose appearance outside the box proves an exploit.

    Any manifest key that names a canary (``canary``, ``file_canary``,
    ``acct_canary``, ...) contributes its value; the ``*_env`` keys that only
    name an environment variable are skipped.
    """
    if not manifest:
        return [_DEFAULT_CANARY]
    out = [
        value
        for key, value in manifest.items()
        if isinstance(value, str) and "canary" in key and not key.endswith("_env")
    ]
    return out or [_DEFAULT_CANARY]


def load_manifest(source_dir: str | None) -> dict | None:
    if not source_dir:
        return None
    path = Path(source_dir) / "manifest.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


def routes_from_manifest(manifest: dict) -> list[Route]:
    routes = []
    for r in manifest.get("routes", []):
        routes.append(Route(method=r.get("method", "GET"), path=r["path"], inputs=list(r.get("inputs", []))))
    return routes


def crawl(base_url: str, seeds: list[str] | None = None, timeout: float = 8.0) -> list[Route]:
    """Fetch a small set of pages and extract linked paths + query params."""
    seen: dict[str, Route] = {}
    to_visit = list(seeds or ["/"])
    visited: set[str] = set()
    origin = urlparse(base_url)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            while to_visit and len(visited) < 15:
                path = to_visit.pop(0)
                # Dedup by bare path (ignoring the query), matching the enqueue
                # guard below, so /product?id=1..N is not re-fetched once per id.
                bare = urlparse(path).path or "/"
                if bare in visited:
                    continue
                visited.add(bare)
                url = urljoin(base_url, path)
                try:
                    resp = client.get(url)
                except httpx.HTTPError:
                    continue
                parsed = urlparse(url)
                inputs = [{"name": k, "source": "query"} for k in parse_qs(parsed.query)]
                key = parsed.path
                if key not in seen:
                    seen[key] = Route(method="GET", path=key, inputs=inputs)
                else:
                    for i in inputs:
                        if i not in seen[key].inputs:
                            seen[key].inputs.append(i)
                if "text/html" in resp.headers.get("content-type", ""):
                    for href in _HREF.findall(resp.text):
                        target = urlparse(urljoin(url, href))
                        if target.netloc and target.netloc != origin.netloc:
                            continue
                        link = target.path + (f"?{target.query}" if target.query else "")
                        if target.path not in visited:
                            to_visit.append(link)
    except httpx.HTTPError:
        pass
    return list(seen.values())


def recon(base_url: str, source_dir: str | None = None) -> tuple[list[Route], dict | None]:
    """Return (routes, manifest). Manifest routes take precedence; crawl fills gaps."""
    manifest = load_manifest(source_dir)
    routes: dict[str, Route] = {}
    if manifest:
        # The manifest is authoritative for seeded targets; skip the live crawl
        # (up to 15 HTTP fetches) on the hot path when it fully defines the surface.
        for r in routes_from_manifest(manifest):
            routes[r.path] = r
    else:
        for r in crawl(base_url):
            routes[r.path] = r
    return list(routes.values()), manifest
