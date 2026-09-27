import base64
import io
import json
import re
import subprocess
import urllib.request
import zlib
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from diagnostic_storage import presign_nic_post, presign_source_get, read_nic_object, validated_storage_target
from instance_lifecycle import docker_user_data, validated_presigned_nic_post, validated_presigned_source_get


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


# --- Presigned single-object GET for disposable target source handoff ---

SOURCE_BUCKET = "cerberus-target-src"
SOURCE_KEY = "src/" + "b" * 32 + ".tgz"


@pytest.fixture
def source_client():
    return boto3.client(
        "s3", region_name="ord1", endpoint_url="https://ord1.vultrobjects.com",
        aws_access_key_id="test-access", aws_secret_access_key="test-secret",
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )


def source_query(expires="900", signature="a" * 64, algorithm="AWS4-HMAC-SHA256"):
    return (
        f"X-Amz-Algorithm={algorithm}&X-Amz-Credential=test-access%2F20260927%2Ford1%2Fs3%2Faws4_request"
        f"&X-Amz-Date=20260927T000000Z&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host&X-Amz-Signature={signature}"
    )


def build_source_url(scheme="https", host=None, path=None, query=None, fragment=""):
    host = host if host is not None else f"{SOURCE_BUCKET}.ord1.vultrobjects.com"
    path = f"/{SOURCE_KEY}" if path is None else path
    query = source_query() if query is None else query
    url = f"{scheme}://{host}{path}"
    if query:
        url += f"?{query}"
    if fragment:
        url += f"#{fragment}"
    return url


def test_presigned_source_get_targets_one_private_bounded_object(source_client):
    url = presign_source_get(source_client, "https://ord1.vultrobjects.com", SOURCE_BUCKET, SOURCE_KEY, expires_in=600)
    assert validated_presigned_source_get(url) == url
    parsed = urlsplit(url)
    assert parsed.scheme == "https"
    assert parsed.netloc == f"{SOURCE_BUCKET}.ord1.vultrobjects.com"
    assert parsed.path == f"/{SOURCE_KEY}" and not parsed.fragment
    params = parse_qs(parsed.query)
    assert params["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert params["X-Amz-Expires"] == ["600"]
    assert re.fullmatch(r"[0-9a-f]{64}", params["X-Amz-Signature"][0])
    assert "test-secret" not in url


@pytest.mark.parametrize("expires_in", [59, 901, 9000, True, "900", 900.0])
def test_presigned_source_get_bounds_its_expiry(source_client, expires_in):
    with pytest.raises(ValueError, match="expiry"):
        presign_source_get(source_client, "https://ord1.vultrobjects.com", SOURCE_BUCKET, SOURCE_KEY, expires_in=expires_in)


@pytest.mark.parametrize("key", [
    "nic/" + "a" * 32 + ".json",
    "src/../" + "b" * 32 + ".tgz",
    "src//" + "b" * 32 + ".tgz",
    "src/" + "b" * 31 + ".tgz",
    "src/" + "B" * 32 + ".tgz",
    "src/" + "b" * 32 + ".tar.gz",
    "src/" + "b" * 32 + ".tgz ",
])
def test_presigned_source_get_rejects_other_or_ambiguous_objects(source_client, key):
    with pytest.raises(ValueError):
        presign_source_get(source_client, "https://ord1.vultrobjects.com", SOURCE_BUCKET, key)


def test_presigned_source_get_requires_the_validated_client_endpoint_and_bucket(source_client):
    with pytest.raises(ValueError):
        presign_source_get(source_client, "https://ewr1.vultrobjects.com", SOURCE_BUCKET, SOURCE_KEY)
    with pytest.raises(ValueError):
        presign_source_get(source_client, "https://ord1.vultrobjects.com", "Invalid_Bucket", SOURCE_KEY)


@pytest.mark.parametrize("mutations", [
    {"scheme": "http"},
    {"host": "ord1.vultrobjects.com"},
    {"host": f"{SOURCE_BUCKET}.ord1.vultrobjects.com.evil.example"},
    {"host": f"user@{SOURCE_BUCKET}.ord1.vultrobjects.com"},
    {"host": f"{SOURCE_BUCKET}.ord1.vultrobjects.com:8443"},
    {"host": f"{SOURCE_BUCKET.upper()}.ord1.vultrobjects.com"},
    {"path": "/src/../" + SOURCE_KEY},
    {"path": "//" + SOURCE_KEY},
    {"path": f"/{SOURCE_KEY}/"},
    {"path": f"/{SOURCE_KEY.replace('.tgz', '')}..tgz"},
    {"query": ""},
    {"query": "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900"},
    {"query": source_query(expires="3600")},
    {"query": source_query(expires="abc")},
    {"query": source_query(signature="z" * 64)},
    {"query": source_query(algorithm="AWS2-HMAC-SHA1")},
    {"fragment": "frag"},
])
def test_validated_presigned_source_get_rejects_foreign_traversal_or_unsigned_urls(mutations):
    with pytest.raises(ValueError):
        validated_presigned_source_get(build_source_url(**mutations))
