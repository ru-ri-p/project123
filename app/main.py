from fastapi import FastAPI

# FastAPI: the web framework. The `app` object is the application that the
# uvicorn server runs; decorators below register URL routes onto it.
app = FastAPI(title="Attest API", version="0.1.0")


@app.get("/health")
def health():
    # Liveness probe. In production, monitoring/load balancers ping this to
    # confirm the service is up before routing traffic to it.
    return {"status": "ok", "service": "attest"}
