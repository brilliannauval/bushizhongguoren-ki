from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.formparsers import MultiPartParser

from .api.errors import install_error_handlers
from .api.middleware import BodyLimitMiddleware, SecurityHeadersMiddleware
from .api.routes import router as api_router
from .runtime import lifespan

# Keep accepted uploads in memory instead of rolling plaintext to a temporary file.
MultiPartParser.spool_max_size = 21 * 1024 * 1024

app = FastAPI(
    title="SecureBox API",
    version="1.0.0",
    description="Owner-scoped educational file vault. RC4 and DES are legacy comparison algorithms only.",
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(BodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
install_error_handlers(app)
app.include_router(api_router)
app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
