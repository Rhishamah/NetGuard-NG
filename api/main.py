from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.config import settings
from api.database import Base, engine

# Import models so SQLAlchemy registers them
from api.models.alert import Alert
from api.routers import status


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs once during application startup.
    """

    print("Starting NetGuard-NG API...")

    Base.metadata.create_all(bind=engine)

    yield

    print("Shutting down NetGuard-NG API...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.include_router(status.router)