import base64
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from diagnostic_receiver import validated_nic_report


def validated_storage_target(endpoint, bucket):
    try:
        url = urlsplit(endpoint)
        host = url.hostname
        port = url.port
    except (TypeError, ValueError):
        raise ValueError("Object Storage endpoint must use a Vultr HTTPS hostname") from None
    if (
        url.scheme != "https" or not host or url.netloc != host or url.geturl() != endpoint or port is not None
        or url.path or url.query or url.fragment or not re.fullmatch(r"[a-z0-9-]{2,32}\.vultrobjects\.com", host)
        or not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket)
    ):
        raise ValueError("Object Storage endpoint or bucket is not approved")
    return endpoint


def presign_nic_post(client, endpoint, bucket, key, expires_in=900):
    validated_storage_target(endpoint, bucket)
    if getattr(client.meta, "endpoint_url", None) != endpoint or not isinstance(key, str) or not re.fullmatch(r"nic/[0-9a-f]{32}\.json", key):
        raise ValueError("Presigned NIC upload must target one private object")
    if type(expires_in) is not int or not 60 <= expires_in <= 900:
        raise ValueError("Presigned NIC upload expiry must be bounded")
    form = client.generate_presigned_post(
        Bucket=bucket, Key=key,
        Fields={"Content-Type": "application/json"},
        Conditions=[{"Content-Type": "application/json"}, ["content-length-range", 1, 4096]],
        ExpiresIn=expires_in,
    )
    host = urlsplit(endpoint).hostname
    if form.get("url") != f"https://{bucket}.{host}/":
        raise ValueError("Presigned NIC upload URL is not the approved bucket")
    fields = form.get("fields", {})
    try:
        policy = json.loads(base64.b64decode(fields["policy"], validate=True))
        expiry = datetime.fromisoformat(policy["expiration"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        raise ValueError("Presigned NIC upload policy is invalid") from None
    conditions = policy.get("conditions", [])
    if (
        fields.get("key") != key or fields.get("Content-Type") != "application/json"
        or {"bucket": bucket} not in conditions or {"key": key} not in conditions
        or {"Content-Type": "application/json"} not in conditions
        or ["content-length-range", 1, 4096] not in conditions
        or not 0 < (expiry - datetime.now(timezone.utc)).total_seconds() <= expires_in
    ):
        raise ValueError("Presigned NIC upload policy does not restrict its object, size and expiry")
    return form


def read_nic_object(client, bucket, key, vpc_subnet):
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return None
        raise
    if response.get("ContentType") != "application/json":
        raise ValueError("NIC object content type is invalid")
    return validated_nic_report(response["Body"].read(257), vpc_subnet)
