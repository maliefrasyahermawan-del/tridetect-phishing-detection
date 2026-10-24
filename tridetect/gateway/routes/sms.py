import hashlib
import time

from fastapi import APIRouter, HTTPException

from tridetect.gateway.schemas import SmsClassifyRequest, SmsClassifyResponse
from tridetect.modules.smishing.classifier import SmishingClassifier
from tridetect.shared.db import log_classification
from tridetect.shared.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/v1/classify", tags=["sms"])

_classifier = SmishingClassifier()


@router.post("/sms", response_model=SmsClassifyResponse)
async def classify_sms(req: SmsClassifyRequest) -> SmsClassifyResponse:
    cache_key = hashlib.md5(req.text.encode()).hexdigest()

    t0 = time.perf_counter()
    try:
        result = _classifier.classify(req.text, sender_number=req.sender_number)
    except Exception as exc:
        logger.error("SMS classification error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    latency_ms = int((time.perf_counter() - t0) * 1000)
    response = SmsClassifyResponse(
        label=result["label"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        module="sms",
        latency_ms=latency_ms,
        urls_found=result.get("urls_found", []),
        urgency_score=result.get("urgency_score", 0),
        sender_reputation=result.get("sender_reputation"),
    )

    log_classification(
        module="sms",
        input_hash=cache_key,
        label=response.label,
        confidence=response.confidence,
        reasons=response.reasons,
        latency_ms=latency_ms,
    )
    return response
