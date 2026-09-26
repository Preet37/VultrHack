from fastapi import FastAPI, Header, HTTPException, Response

from instance_lifecycle import ReadySignals

app = FastAPI(title="Cerberus")
ready_signals = ReadySignals()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/ready")
async def instance_ready(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer ") or not ready_signals.signal(authorization[7:]):
        raise HTTPException(status_code=404)
    return Response(status_code=204)
