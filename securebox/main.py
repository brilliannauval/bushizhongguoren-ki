from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.formparsers import MultiPartParser

from .config import get_settings
from .api.errors import install_error_handlers
from .api.middleware import BodyLimitMiddleware, SecurityHeadersMiddleware
from .api.routes import router as api_router
from .runtime import lifespan

MultiPartParser.spool_max_size = 21 * 1024 * 1024

app = FastAPI(
    title="SecureBox API",
    version="1.0.0",
    description="Owner-scoped educational file vault. RC4 and DES are legacy comparison algorithms only.",
    docs_url="/api/docs" if get_settings().app_env == "development" else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if get_settings().app_env == "development" else None,
    lifespan=lifespan,
)
app.add_middleware(BodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
install_error_handlers(app)
app.include_router(api_router)
app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
allowed_hosts = ["localhost", "127.0.0.1", "::1", "testserver", "securebox", "gateway"]
if get_settings().public_origin:
    public_host = urlsplit(get_settings().public_origin).hostname
    if public_host:
        allowed_hosts.append(public_host)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
