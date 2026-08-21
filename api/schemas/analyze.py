from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Request body for starting a traffic analysis."""

    interface: str = Field(
        ...,
        min_length=1,
        description="Network interface to capture traffic from",
        examples=["eth0"],
    )


class AnalyzeResponse(BaseModel):
    """Response returned after traffic analysis."""

    prediction: str
    confidence: float
    severity: str