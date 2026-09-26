# Cerberus

<img src="cerberus-logo.jpg" alt="Cerberus logo" width="240">

A FastAPI orchestrator for isolated, defensive repository checks. The first milestone provides a health endpoint and a command to verify access to Vultr APIs without printing credentials.

## Local setup

Requires Python 3.11 or newer.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
```

Set `VULTR_API_KEY` and `VULTR_INFERENCE_KEY` in `.env` or your environment. The existing lowercase `.env` variable names are also accepted. Never commit `.env`.

```sh
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
.venv/bin/python -m connectivity
.venv/bin/python -m pytest -q
```

`GET /` displays the Cerberus logo, and `GET /logo.jpg` serves the image for future clients. `GET /health` returns `{"status": "ok"}`. The connectivity command fetches `/v1/models`, verifies account-key access with `/v2/account`, and fetches `/v2/regions` before printing the successful statuses and available model IDs.

## Temporary instance check

The lifecycle command provisions one Ubuntu 24.04 instance, installs Docker via cloud-init, waits for a readiness callback, and deletes the instance even if provisioning or readiness fails after the API returns an instance ID. It confirms deletion by polling for a 404. Neither Vultr key is included in cloud-init; the callback uses a separate, short-lived token.

Provide a publicly reachable HTTPS URL that forwards `/internal/ready` to port 8000 of the machine running the command. Stop any other server using that port first. The command opens a callback-only server (no home page, docs, or other API routes), and `--execute` is required because this creates a billable VM and deletes it afterward:

```sh
.venv/bin/python -m instance_lifecycle --callback-url https://YOUR-HTTPS-HOST/internal/ready --execute
```

The default region is `ewr`, plan `vc2-1c-1gb`, and OS ID `2284`. Override region and plan via `VULTR_REGION` and `VULTR_PLAN` in `.env` or use `--region` and `--plan`. The application name and API title are Cerberus; this does not rename the GitHub repository or your local directory.

For a temporary Cloudflared tunnel, run `cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8000` in another terminal. Append `/internal/ready` to the HTTPS URL it prints. Alternatively, if NetBird Peer Expose is enabled and the client is connected, run `netbird expose 8000` and use its HTTPS URL the same way. Stop the tunnel when the check finishes. The readiness endpoint requires a random, per-run bearer token, so do not add proxy authentication that cloud-init cannot supply.
