"""Static safety gate for the (UNTRUSTED) remediation agent's patches.

The fixer agent writes code. We do not trust it. Before a patch is ever applied,
this gate statically inspects the *added* lines of its unified diff and rejects
anything that looks destructive, that weakens auth, that exfiltrates secrets, or
that "cheats" the re-exploit check by nuking the target instead of fixing it.

This is a belt-and-suspenders layer *in front of* the existing re-exploit +
functional + independent-review gates in ``finder/remediate.py``: those prove a
patch *closes the class without breaking behavior*; this one catches a patch that
would close the class by doing something catastrophic (``rm -rf`` the file,
``DROP TABLE`` the database, disable auth globally, phone home, read /etc/shadow).

Design contract:
  * It only reads ADDED lines (``+`` but not ``+++``) for "newly introduced"
    patterns, and consults REMOVED lines (``-`` but not ``---``) only to detect
    an auth/ownership check that was deleted and never re-added.
  * ZERO false positives on our real remediation fixes. In particular the real
    SSRF fix legitimately adds ``import ipaddress`` / ``import socket`` /
    ``from urllib.parse import urlparse`` plus an allow-list built on
    ``urlparse()`` / ``ip_address()`` / ``socket.gethostbyname()`` -- none of
    that may be flagged. Only genuine *outbound calls* newly added are network
    hits, and bare imports never are.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class GateResult:
    """The verdict. ``ok`` is False when any dangerous pattern was found."""

    ok: bool
    hits: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "hits": list(self.hits)}


# --- Added-line rules: (rule, reason, compiled pattern) ----------------------
# Each pattern is matched against a single ADDED line (with its leading '+'
# stripped). A match is a hit. Kept deliberately narrow so legit fixes pass.

_ADDED_RULES: list[tuple[str, str, re.Pattern]] = [
    # ---- file deletion / destruction ----
    ("file_destruction", "shell file deletion (rm -rf) introduced", re.compile(r"\brm\s+-[a-zA-Z]*[rf]")),
    ("file_destruction", "recursive tree deletion (shutil.rmtree) introduced", re.compile(r"shutil\s*\.\s*rmtree\s*\(")),
    ("file_destruction", "file deletion (os.remove) introduced", re.compile(r"os\s*\.\s*remove\s*\(")),
    ("file_destruction", "file deletion (os.unlink) introduced", re.compile(r"os\s*\.\s*unlink\s*\(")),
    ("file_destruction", "file deletion (.unlink()) introduced", re.compile(r"\.\s*unlink\s*\(")),
    ("file_destruction", "directory deletion (os.rmdir) introduced", re.compile(r"os\s*\.\s*rmdir\s*\(")),
    # ---- permission weakening (world-writable chmod) ----
    (
        "permission_weakening",
        "world-writable chmod introduced (masks the bug instead of fixing it)",
        re.compile(r"chmod\s*\([^)]*\b(0o?777|0o?666|511|438)\b"),
    ),
    # ---- shell execution ----
    ("shell_execution", "shell=True enables shell interpretation of input", re.compile(r"shell\s*=\s*True\b")),
    ("shell_execution", "os.system() runs a shell command", re.compile(r"os\s*\.\s*system\s*\(")),
    ("shell_execution", "os.popen() runs a shell command", re.compile(r"os\s*\.\s*popen\s*\(")),
    ("shell_execution", "backtick command substitution introduced", re.compile(r"`")),
    # ---- dynamic code execution ----
    ("dynamic_code", "eval() executes arbitrary code", re.compile(r"(?<![\w.])eval\s*\(")),
    ("dynamic_code", "exec() executes arbitrary code", re.compile(r"(?<![\w.])exec\s*\(")),
    ("dynamic_code", "__import__() dynamic import introduced", re.compile(r"__import__\s*\(")),
    ("dynamic_code", "pickle.loads() deserializes untrusted data", re.compile(r"pickle\s*\.\s*loads\s*\(")),
    # ---- destructive SQL ----
    ("destructive_sql", "DROP TABLE destroys data", re.compile(r"(?i)\bdrop\s+table\b")),
    ("destructive_sql", "TRUNCATE destroys data", re.compile(r"(?i)\btruncate\b")),
    ("destructive_sql", "stacked '; DROP' injection introduced", re.compile(r"(?i);\s*drop\b")),
    # ---- auth weakening (added toggles) ----
    ("auth_weakening", "auth flag disabled (AUTH... = False)", re.compile(r"(?i)\bauth[a-z0-9_]*\s*=\s*false\b")),
    ("auth_weakening", "check_auth disabled (= False)", re.compile(r"(?i)\bcheck_auth[a-z0-9_]*\s*=\s*false\b")),
    ("auth_weakening", "TLS/cert verification disabled (verify=False)", re.compile(r"(?i)\bverify\s*=\s*false\b")),
    ("auth_weakening", "permissive auth stub (permit_all)", re.compile(r"(?i)\bpermit_all\b")),
    ("auth_weakening", "permissive auth stub (allow_any)", re.compile(r"(?i)\ballow_any\b")),
    # ---- new outbound network CALLS (imports handled separately, never flagged) ----
    ("network_call", "new outbound HTTP call (requests.*) introduced", re.compile(r"\brequests\s*\.\s*(get|post|put|patch|delete|head|request)\s*\(")),
    ("network_call", "new outbound call (urllib.request.urlopen) introduced", re.compile(r"urllib\s*\.\s*request\s*\.\s*urlopen\s*\(")),
    ("network_call", "raw urlopen() outbound call introduced", re.compile(r"(?<![\w.])urlopen\s*\(")),
    ("network_call", "raw socket connection introduced", re.compile(r"\bsocket\s*\.\s*connect\s*\(")),
    ("network_call", "http.client outbound connection introduced", re.compile(r"\bhttp\s*\.\s*client\s*\.")),
    # ---- reading known credential files ----
    ("secret_read", "reads private SSH key (id_rsa)", re.compile(r"id_rsa\b")),
    ("secret_read", "reads /etc/shadow", re.compile(r"/etc/shadow\b")),
    ("secret_read", "reads /etc/passwd", re.compile(r"/etc/passwd\b")),
    ("secret_read", "opens a .env secrets file", re.compile(r"\.env\b")),
]

# Newly-added read of an environment secret: needs BOTH an environ/getenv access
# AND a name that looks like a secret. Split into two so os.environ used for a
# benign name is not flagged.
_ENVIRON_ACCESS = re.compile(r"(?i)(os\s*\.\s*environ|getenv)")
_SECRET_NAME = re.compile(r"""(?i)['"][^'"]*(SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|\bKEY\b|AWS_)[^'"]*['"]""")

# A line that is purely an import statement -- never a network hit (a legit fix
# is allowed to `import socket` / `from urllib.parse import urlparse`).
_IMPORT_LINE = re.compile(r"^\s*(import\s|from\s+\S+\s+import\s)")

# --- Removed-line auth signatures --------------------------------------------
# If a patch DELETES one of these and does not re-add the same keyword on any
# added line, it is dropping an authorization/ownership check (classic IDOR
# "fix"). Each entry: (compiled pattern, keyword-to-look-for-on-added-lines,
# human reason).
_AUTH_DELETE_SIGNATURES: list[tuple[re.Pattern, re.Pattern, str]] = [
    (re.compile(r"login_required"), re.compile(r"login_required"), "@login_required decorator was removed"),
    (re.compile(r"current_user"), re.compile(r"current_user"), "an ownership check against current_user was removed"),
    (re.compile(r"(?i)abort\s*\(\s*40[13]"), re.compile(r"(?i)abort\s*\(\s*40[13]"), "an auth abort(401/403) was removed"),
    (re.compile(r"(?i)\bpermission"), re.compile(r"(?i)\bpermission"), "a permission check was removed"),
    (re.compile(r"(?i)\b(authorize|authorized|authenticate|authenticated|is_authenticated)\b"),
     re.compile(r"(?i)\b(authorize|authorized|authenticate|authenticated|is_authenticated)\b"),
     "an authorization/authentication check was removed"),
    (re.compile(r"(?i)\bis_admin\b"), re.compile(r"(?i)\bis_admin\b"), "an admin check was removed"),
    (re.compile(r"(?i)(!=|==)[^\n]*\b(owner|user_id|owner_id)\b"),
     re.compile(r"(?i)(!=|==)[^\n]*\b(owner|user_id|owner_id)\b"),
     "an ownership comparison guard was removed"),
]


def _added_lines(diff: str) -> list[str]:
    return [ln[1:] for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def _removed_lines(diff: str) -> list[str]:
    return [ln[1:] for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---")]


def safety_gate(diff: str) -> GateResult:
    """Statically inspect a unified diff of a proposed patch.

    Returns ``GateResult(ok=False, hits=[...])`` when any dangerous / cheating
    pattern is found on the added lines (or an auth check is deleted), else
    ``GateResult(ok=True, hits=[])``.
    """
    hits: list[dict] = []
    added = _added_lines(diff or "")
    removed = _removed_lines(diff or "")
    added_joined = "\n".join(added)

    for raw in added:
        line = raw.rstrip("\n")
        stripped = line.strip()
        is_import = bool(_IMPORT_LINE.match(line))
        for rule, reason, pattern in _ADDED_RULES:
            if rule == "network_call" and is_import:
                # A legit fix may import socket / urllib etc.; only CALLS count.
                continue
            if pattern.search(line):
                hits.append({"rule": rule, "reason": reason, "line": stripped})

        # DELETE FROM ... without a WHERE clause (deletes every row).
        if re.search(r"(?i)\bdelete\s+from\b", line) and not re.search(r"(?i)\bwhere\b", line):
            hits.append({"rule": "destructive_sql", "reason": "DELETE FROM without a WHERE clause wipes the table", "line": stripped})

        # Newly-added read of an environment secret (both signals must be present).
        if _ENVIRON_ACCESS.search(line) and _SECRET_NAME.search(line):
            hits.append({"rule": "secret_read", "reason": "reads a credential/secret from the environment", "line": stripped})

    # Deleted auth/ownership checks that are not re-added anywhere.
    for raw in removed:
        line = raw.rstrip("\n")
        stripped = line.strip()
        for pattern, readd, reason in _AUTH_DELETE_SIGNATURES:
            if pattern.search(line) and not readd.search(added_joined):
                hits.append({"rule": "auth_weakening", "reason": reason, "line": stripped})

    return GateResult(ok=not hits, hits=hits)


__all__ = ["GateResult", "safety_gate"]
