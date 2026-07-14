from fastapi import APIRouter

router = APIRouter(
    prefix="",
    tags=["Status"],
)


@router.get("/")
def root():
    return {
        "message": "Welcome to NetGuard-NG API",
        "version": "1.0.0",
    }


@router.get("/status")
def get_status():
    return {
        "status": "healthy",
        "database": "connected",
        "model": "loaded",
    }