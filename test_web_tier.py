import base64
import subprocess

import pytest  # noqa

from web_tier import build_create_web_tier_payload, web_tier_user_data


SHA = "a" * 40


def test_web_tier_user_data_syntax_and_contents():
    script = web_tier_user_data(SHA, "NB" + "k" * 38, "C" * 40, "demo-pass", "W" * 48)
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    assert SHA in script
    assert "systemctl mask ssh.socket ssh.service" in script
    assert 'netbird up --setup-key' in script
    assert "--port 443" in script and "uvicorn web_proxy:app" in script
    assert "ufw allow 443/tcp" in script and "ufw default deny incoming" in script
    assert 'CERBERUS_CONTROL_URL=http://100.124.55.15:8000' in script
    assert "demo-pass" in script  # web tier legitimately holds the demo password


def test_web_tier_enforces_pinned_sha_and_safe_values():
    with pytest.raises(ValueError):
        web_tier_user_data("notasha", "NB" + "k" * 38, "C" * 40, "demo-pass", "W" * 48)
    with pytest.raises(ValueError):
        web_tier_user_data(SHA, "NB" + "k" * 38, "C" * 40, "pass'word", "W" * 48)
    with pytest.raises(ValueError):
        web_tier_user_data(SHA, "NB" + "k" * 38, "C" * 40, "demo-pass", "W" * 48 + "\nsneaky")


def test_create_web_tier_payload_shape():
    payload = build_create_web_tier_payload(web_tier_user_data(SHA, "NB" + "k" * 38, "C" * 40, "demo-pass", "W" * 48), "ord", "vc2-1c-1gb")
    assert payload["region"] == "ord" and payload["plan"] == "vc2-1c-1gb"
    assert payload["tags"] == ["cerberus-web"]
    decoded = base64.b64decode(payload["user_data"]).decode()
    assert "cerberus-web.service" in decoded
    with pytest.raises(ValueError):
        build_create_web_tier_payload("x", "ord", "vx1-g-2c-8g-120s")
