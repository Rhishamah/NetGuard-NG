from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.config import settings
from api.database import Base, engine

# Import models so SQLAlchemy registers them
from api.models.alert import Alert
from api.routers import status

# import model registry
from api.services.model_registry import registry

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

app.include_router(status.router)