from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from api.config import settings
from api.dependencies import get_db

router = APIRouter(
    tags=["System"],
)


@router.get("/")
def root():
    # Root endpoint.
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
    }


@router.get("/status")
def status(db: Session = Depends(get_db)):
    # Health check endpoint. verifies real system state, not just a static response
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unreachable"

        return{
            "status":"healthy" if db_status == "connected" else "degraded",
            "database": db_status,
            "app_version":settings.app_version,
        }