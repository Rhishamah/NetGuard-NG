from collections.abc import Generator
from sqlalchemy.orm import Session
from api.database import SessionLocal

def get_db() -> Generator[Session, None, None]:
    # creates a new database session for each request
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()