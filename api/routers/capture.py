import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from api.auth import get_current_admin
from api.limiter import limiter
from api.services.capture_service import (
    run_live_capture,
    capture_lock,
)


router = APIRouter(
    prefix="/capture",
    tags=["Capture"],
    dependencies=[Depends(get_current_admin)],
)


_capture_running = False
_task: asyncio.Task | None = None
_stop_event: asyncio.Event | None = None


class CaptureRequest(BaseModel):
    interface: str
    duration_seconds: int = 60
    output_path: str = "data/capture.csv"


async def _run(request: CaptureRequest):
    global _capture_running

    async with capture_lock:
        try:
            await run_live_capture(
                request.interface,
                request.duration_seconds,
                request.output_path,
                _stop_event,
            )
        finally:
            _capture_running = False


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def start_capture(
    request: Request,
    body: CaptureRequest,
):
    global _capture_running, _task, _stop_event

    if _capture_running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Capture already running",
        )

    _capture_running = True
    _stop_event = asyncio.Event()

    _task = asyncio.create_task(_run(body))

    return {
        "message": "Capture started",
        "output": body.output_path,
        "duration_seconds": body.duration_seconds,
        "interface": body.interface,
    }


@router.post("/stop", status_code=status.HTTP_200_OK)
async def stop_capture():
    global _stop_event

    if not _capture_running or _stop_event is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No capture running",
        )

    _stop_event.set()

    return {
        "message": "Capture stop requested",
    }


@router.get("/status")
def capture_status():
    return {
        "running": _capture_running,
    }