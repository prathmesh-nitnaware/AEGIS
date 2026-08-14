from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.telemetry import router as telemetry_router


app = FastAPI(
    title="AEGIS Command API",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(telemetry_router)


@app.get("/")
def root():
    return {
        "name": "AEGIS",
        "status": "online",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "aegis-backend",
    }


if __name__ == "__main__":
    import os
    import sys
    import uvicorn

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    os.environ["PYTHONPATH"] = project_root + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)


