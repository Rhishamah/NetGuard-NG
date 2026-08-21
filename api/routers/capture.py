import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from api.auth import get_current_admin
from api.limiter import limiter
from api.services.capture_service import run_live_capture, capture_lock

router = APIRouter(prefix="/capture", tags=["Capture"], dependencies=[Depends(get_current_admin)])

_capture_running = False
_task: asyncio.Task | None = None


class CaptureRequest(BaseModel):
    interface: str
    duration_seconds: int = 60
    output_path: str = "data/capture.csv"


async def _run(request: CaptureRequest):
    global _capture_running
    async with capture_lock:
        try:
            await run_live_capture(request.interface, request.duration_seconds, request.output_path)
        finally:
            _capture_running = False


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def start_capture(request: Request, body: CaptureRequest):
    global _capture_running, _task
    if _capture_running:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Capture already running")
    _capture_running = True
    _task = asyncio.create_task(_run(body))
    return {"message": "Capture started", "output": body.output_path}


@router.post("/stop", status_code=status.HTTP_200_OK)
async def stop_capture():
    global _task
    if not _task or _task.done():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No capture running")
    _task.cancel()
    return {"message": "Capture stopped"}


@router.get("/status")
def capture_status():
    return {"running": _capture_running}
