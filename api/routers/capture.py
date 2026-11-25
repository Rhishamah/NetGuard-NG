import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.auth import get_current_admin
from api.limiter import limiter
from api.services.capture_service import (
    run_live_capture,
    capture_lock,
    new_capture_path,
)
from api.services.validation import validate_interface


router = APIRouter(
    prefix="/capture",
    tags=["Capture"],
    dependencies=[Depends(get_current_admin)],
)


_capture_running = False
_task: asyncio.Task | None = None
_stop_event: asyncio.Event | None = None


class CaptureRequest(BaseModel):
    interface: str = Field(..., min_length=1, max_length=32)
    duration_seconds: int = Field(default=60, ge=1, le=300)
    # No output_path: the server chooses the file (see new_capture_path).


async def _run(request: CaptureRequest, output_path: str):
    global _capture_running

    async with capture_lock:
        try:
            await run_live_capture(
                request.interface,
                request.duration_seconds,
                output_path,
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

    validate_interface(body.interface)
    output_path = new_capture_path()

    _capture_running = True
    _stop_event = asyncio.Event()

    _task = asyncio.create_task(_run(body, output_path))

    return {
        "message": "Capture started",
        "output": output_path,
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