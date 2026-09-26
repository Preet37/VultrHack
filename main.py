from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Response
from fastapi.responses import FileResponse, HTMLResponse

from instance_lifecycle import ReadySignals

app = FastAPI(title="Cerberus")
ready_signals = ReadySignals()


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Cerberus</title>'
        '<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>'
        '<main><img src="/logo.jpg" alt="Cerberus logo" width="240" height="240">'
        '<h1>Cerberus</h1><p>Isolated repository checks.</p><a href="/docs">API docs</a></main>'
        '</body></html>'
    )


@app.get("/logo.jpg", response_class=FileResponse, include_in_schema=False)
def logo():
    return FileResponse(Path(__file__).with_name("cerberus-logo.jpg"), media_type="image/jpeg")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/ready")
async def instance_ready(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer ") or not ready_signals.signal(authorization[7:]):
        raise HTTPException(status_code=404)
    return Response(status_code=204)


callback_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
callback_app.add_api_route("/internal/ready", instance_ready, methods=["POST"])
