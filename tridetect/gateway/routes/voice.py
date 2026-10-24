from fastapi import APIRouter
from fastapi.responses import JSONResponse

from tridetect.gateway.schemas import VoiceClassifyRequest

router = APIRouter(prefix="/v1/classify", tags=["voice"])


@router.post("/voice")
async def classify_voice(req: VoiceClassifyRequest) -> JSONResponse:
    """Voice/Vishing classification - Phase 2 stub."""
    return JSONResponse(
        status_code=501,
        content={
            "detail": (
                "Vishing module is not yet implemented (Phase 2). "
                "Planned features: Whisper STT + IndoBERT transcript classification "
                "+ voice clone anomaly detection. "
                "Expected availability: Week 5-7 of development roadmap."
            ),
            "roadmap": {
                "phase2": "Whisper STT + transcript classification",
                "phase3": "Voice clone detection",
            },
        },
    )
