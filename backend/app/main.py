"""ContextShield — FastAPI Application Entry Point."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .core.logging import logger
from .core.exceptions import http_exception_handler
from .api.v1.router import router as v1_router

app = FastAPI(
    title="ContextShield",
    description="Context-aware data privacy enforcement engine for AI agents.",
    version="0.1.0",
)

# CORS configuration based on settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register global exception handler
app.add_exception_handler(HTTPException, http_exception_handler)

# Include API routers
app.include_router(v1_router, prefix="/api/v1")

@app.get("/health", tags=["system"]) 
async def health_check():
    """Basic health check endpoint."""
    return {"status": "ok"}
