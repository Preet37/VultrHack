from fastapi import FastAPI

app = FastAPI(title="Repo Airlock")


@app.get("/health")
def health():
    return {"status": "ok"}
