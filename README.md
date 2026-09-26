# Repo Airlock

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

`GET /health` returns `{"status": "ok"}`. The connectivity command fetches `/v1/models` and `/v2/regions`, then prints both successful statuses and the available model IDs.
