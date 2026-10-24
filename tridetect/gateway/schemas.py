from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class ClassificationResult(BaseModel):
    label: Literal["safe", "suspicious", "malicious"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: list[str]
    module: str
    latency_ms: int
    extra: Optional[dict[str, Any]] = None


class WebClassifyRequest(BaseModel):
    url: str = Field(..., description="URL to classify")
    check_ssl: bool = True
    check_brand: bool = True


class WebClassifyResponse(ClassificationResult):
    brand_match: Optional[str] = None
    ssl_valid: Optional[bool] = None


class SmsClassifyRequest(BaseModel):
    text: str = Field(..., min_length=5, max_length=2000)
    sender_number: Optional[str] = None
    timestamp: Optional[datetime] = None


class SmsClassifyResponse(ClassificationResult):
    urls_found: list[str] = []
    urgency_score: int = Field(0, ge=0, le=100)
    sender_reputation: Optional[str] = None


class VoiceClassifyRequest(BaseModel):
    audio_base64: Optional[str] = None
    audio_path: Optional[str] = None
    language: str = "id"


class VoiceClassifyResponse(ClassificationResult):
    transcript: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    modules: dict[str, str]
