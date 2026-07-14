from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Alert(Base):
    # Database model representing a detected network anomaly.

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    source_ip: Mapped[str] = mapped_column(String(45))

    destination_ip: Mapped[str] = mapped_column(String(45))

    protocol: Mapped[str] = mapped_column(String(20))

    prediction: Mapped[str] = mapped_column(String(20))

    confidence: Mapped[float] = mapped_column(Float)

    severity: Mapped[str] = mapped_column(String(20))