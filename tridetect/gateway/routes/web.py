import hashlib
import time

from fastapi import APIRouter, HTTPException

from tridetect.gateway.schemas import WebClassifyRequest, WebClassifyResponse
from tridetect.modules.web_phishing.classifier import WebPhishingClassifier
from tridetect.shared.cache import url_cache
from tridetect.shared.db import log_classification
from tridetect.shared.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/v1/classify", tags=["web"])

_classifier = WebPhishingClassifier()


@router.post("/web", response_model=WebClassifyResponse)
async def classify_web(req: WebClassifyRequest) -> WebClassifyResponse:
    url_str = str(req.url)
    cache_key = hashlib.md5(url_str.encode()).hexdigest()

    cached = url_cache.get(cache_key)
    if cached:
        logger.info("Cache hit for %s", url_str)
        return WebClassifyResponse(**cached)

    t0 = time.perf_counter()
    try:
        result = _classifier.classify(
            url_str,
            check_ssl=req.check_ssl,
            check_brand=req.check_brand,
        )
    except Exception as exc:
        logger.error("Web classification error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    latency_ms = int((time.perf_counter() - t0) * 1000)
    response = WebClassifyResponse(
        label=result["label"],
        confidence=result["confidence"],
        reasons=result["reasons"],
        module="web",
        latency_ms=latency_ms,
        brand_match=result.get("brand_match"),
        ssl_valid=result.get("ssl_valid"),
    )

    url_cache.set(cache_key, response.model_dump())
    log_classification(
        module="web",
        input_hash=cache_key,
        label=response.label,
        confidence=response.confidence,
        reasons=response.reasons,
        latency_ms=latency_ms,
    )
    return response
