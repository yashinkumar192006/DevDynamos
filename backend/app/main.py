"""ContextShield — FastAPI Application Entry Point."""

from fastapi import FastAPI

app = FastAPI(
    title="ContextShield",
    description="Context-aware data privacy enforcement engine for AI agents.",
    version="0.1.0",
)


@app.get("/health", tags=["system"])
async def health_check():
    """Basic health check endpoint."""
    return {"status": "ok"}
