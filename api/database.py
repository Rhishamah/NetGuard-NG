from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import sessionmaker


from api.config import settings

class Base(DeclarativeBase):
    # base class for all SQLALchemy models
    pass

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread":False},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)