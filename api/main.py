from contextlib import asynccontextmanager

from fastapi import FastAPI

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.config import settings
from api.database import Base, engine
from api.models.alert import Alert
from api.routers import status, alerts, capture, analyze, auth
from api.services.model_registry import registry
from api.limiter import limiter

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once during application startup.
    """

    print("Starting NetGuard-NG API...")

    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)

    print("Loading Random forest model...")
    registry.load()
    
    print("NetGuard-NG API is ready.")

    yield

    print("Shutting down NetGuard-NG API...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(status.router)
app.include_router(alerts.router)
app.include_router(capture.router)
app.include_router(analyze.router)
app.include_router(auth.router)