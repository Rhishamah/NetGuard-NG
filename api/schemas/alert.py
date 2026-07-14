from datetime import datetime

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int

    timestamp: datetime

    source_ip: str

    destination_ip: str

    protocol: str

    prediction: str

    confidence: float

    severity: str

    model_config = {
        "from_attributes": True
    }