import base64
import io
import json
import subprocess
import urllib.request
import zlib
from datetime import datetime, timezone

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from diagnostic_storage import presign_nic_post, read_nic_object, validated_storage_target
from instance_lifecycle import docker_user_data, validated_presigned_nic_post


BUCKET = "cerberus-nic-demo"
KEY = "nic/" + "a" * 32 + ".json"


@pytest.fixture
def presigned_form():
    client = boto3.client(
        "s3", region_name="ord1", endpoint_url="https://ord1.vultrobjects.com",
        aws_access_key_id="test-access", aws_secret_access_key="test-secret",
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )
    return presign_nic_post(client, "https://ord1.vultrobjects.com", BUCKET, KEY, expires_in=900)


def test_presigned_post_limits_one_private_object_and_expiry(presigned_form):
    form = presigned_form
    assert validated_presigned_nic_post(form) == form
    policy = json.loads(base64.b64decode(form["fields"]["policy"]))
    conditions = policy["conditions"]
    assert form["url"] == f"https://{BUCKET}.ord1.vultrobjects.com/"
    assert {"bucket": BUCKET} in conditions
    assert {"key": KEY} in conditions
    assert {"Content-Type": "application/json"} in conditions
    assert ["content-length-range", 1, 4096] in conditions
    assert form["fields"]["Content-Type"] == "application/json"
    assert "acl" not in form["fields"]
    expiry = datetime.fromisoformat(policy["expiration"].replace("Z", "+00:00"))
    assert 0 < (expiry - datetime.now(timezone.utc)).total_seconds() <= 900


def test_presigned_guest_nic_report_precedes_apt_and_stays_bounded(presigned_form, monkeypatch):
    script = docker_user_data(
        "http://10.52.0.3:8001/internal/ready", "R" * 43, True,
        vpc_callback=True, vpc_subnet="10.52.0.0/24", diagnostic_upload=presigned_form,
    )
    assert len(base64.b64encode(script.encode())) < 16 * 1024
    head, wrapped = script.split("vpc_payload=$(python3 -c ", 1)
    blob = wrapped.split(") && eval", 1)[0].rsplit(" ", 1)[-1]
    expanded = head + zlib.decompress(base64.b64decode(blob)).decode()
    assert subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True).returncode == 0
    assert subprocess.run(["sh", "-n"], input=expanded, text=True, capture_output=True).returncode == 0
    assert expanded.index("form=json.loads") < expanded.index("apt-get update")
    code = expanded.split("python3 - <<'PY'\n")[2].split("\nPY\n", 1)[0]
    seen = {}

    def urlopen(request, timeout):
        seen.update(url=request.full_url, content_type=request.get_header("Content-type"), body=request.data, timeout=timeout)
        return io.BytesIO(b"")

    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: json.dumps([{"ifname": "ens7", "addr_info": [{"family": "inet", "local": "10.52.0.4"}]}]))
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    exec(compile(code, "<presigned-guest-nic>", "exec"), {})
    assert seen["url"] == presigned_form["url"]
    assert seen["content_type"].startswith("multipart/form-data; boundary=")
    assert b'"vpc_ip": "10.52.0.4"' in seen["body"]
    assert b'test-secret' not in seen["body"]
    assert len(seen["body"]) <= 4096 and seen["timeout"] == 5


@pytest.mark.parametrize("endpoint,bucket", [
    ("http://ord1.vultrobjects.com", BUCKET),
    ("https://user@ord1.vultrobjects.com", BUCKET),
    ("https://ord1.vultrobjects.com:443", BUCKET),
    ("https://ord1.vultrobjects.com.evil.example", BUCKET),
    ("https://ord1.vultrobjects.com/path", BUCKET),
    ("https://ord1.vultrobjects.com", "Bad_Bucket"),
])
def test_storage_target_rejects_unapproved_locations(endpoint, bucket):
    with pytest.raises(ValueError):
        validated_storage_target(endpoint, bucket)


def test_private_object_reader_is_bounded_and_distinguishes_missing_objects():
    class Store:
        body = b'{"probe":"ok","vpc_ip":"10.52.0.4"}'
        content_type = "application/json"
        missing = False

        def get_object(self, Bucket, Key):
            assert (Bucket, Key) == (BUCKET, KEY)
            if self.missing:
                raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "not found"}}, "GetObject")
            return {"Body": io.BytesIO(self.body), "ContentType": self.content_type}

    store = Store()
    assert read_nic_object(store, BUCKET, KEY, "10.52.0.0/24") == {"probe": "ok", "vpc_ip": "10.52.0.4"}
    store.missing = True
    assert read_nic_object(store, BUCKET, KEY, "10.52.0.0/24") is None
    store.missing = False
    store.body = b"x" * 257
    with pytest.raises(ValueError):
        read_nic_object(store, BUCKET, KEY, "10.52.0.0/24")
    store.body = b'{"probe":"ok","vpc_ip":null}'
    store.content_type = "text/html"
    with pytest.raises(ValueError):
        read_nic_object(store, BUCKET, KEY, "10.52.0.0/24")
