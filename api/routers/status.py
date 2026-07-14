from fastapi import APIRouter

from api.config import settings

router = APIRouter(
    tags=["System"],
)


@router.get("/")
def root():
    """
    Root endpoint.
    """
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
    }


@router.get("/status")
def status():
    # Health check endpoint.
    return {
        "status": "healthy",
        "database": "connected",
        "model": "loaded",
    }