from fastapi import APIRouter

from backend.services.telemetry_service import (
    get_events,
    get_model_results,
    get_stats,
)


router = APIRouter(
    prefix="/api/telemetry",
    tags=["Telemetry"],
)


@router.get("/events")
def events():
    return {
        "events": get_events(),
    }


@router.get("/detections")
def detections():
    return {
        "detections": get_model_results(),
    }


@router.get("/stats")
def stats():
    return get_stats()

