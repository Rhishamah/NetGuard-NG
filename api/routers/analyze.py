from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api.auth import get_current_admin
from api.dependencies import get_db
from api.limiter import limiter
from api.models.alert import Alert
from api.schemas.analyze import AnalyzeRequest, AnalyzeResponse
from api.services.analyzer import analyze_capture
from api.services.capture_service import run_live_capture, capture_lock
from api.services.model_registry import registry

router = APIRouter(prefix="/analyze", tags=["Analyze"], dependencies=[Depends(get_current_admin)])

CAPTURE_PATH = "data/live_capture.csv"


@router.post("/", response_model=AnalyzeResponse)
@limiter.limit("5/minute")
async def analyze(request: Request, body: AnalyzeRequest, db: Session = Depends(get_db)):
    if capture_lock.locked():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A capture is already running")
    try:
        async with capture_lock:
            await run_live_capture(body.interface, 60, CAPTURE_PATH)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))

    try:
        rf = registry.get_random_forest()
        result = analyze_capture(CAPTURE_PATH, rf)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    alert = Alert(
        source_ip="N/A",
        destination_ip="N/A",
        protocol="N/A",
        prediction=result["prediction"],
        confidence=result["confidence"],
        severity=result["severity"],
    )
    db.add(alert)
    db.commit()

    return AnalyzeResponse(**result)
