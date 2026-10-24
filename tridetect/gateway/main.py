from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tridetect import __version__
from tridetect.gateway.routes import sms, voice, web
from tridetect.gateway.schemas import HealthResponse
from tridetect.shared.db import init_db
from tridetect.shared.logger import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Tridetect API starting up — version %s", __version__)
    init_db()
    yield
    logger.info("Tridetect API shutting down")


app = FastAPI(
    title="Tridetect API",
    description="Tri-vector Phishing Detection: Web + Smishing + Vishing (Phase 2)",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(web.router)
app.include_router(sms.router)
app.include_router(voice.router)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        modules={
            "web": "active",
            "sms": "active",
            "voice": "stub_phase2",
        },
    )


@app.get("/")
async def root():
    return {
        "name": "Tridetect",
        "description": "Tri-vector Phishing Detection System",
        "docs": "/docs",
        "version": __version__,
    }
