"""OnionDrop - Minimal, secure, password-protected, Tor-hosted file upload service.

Strict security guarantees:
- Zero download endpoints.
- Zero file listing endpoints.
- Zero file previews.
- Files stored outside web root with non-executable permissions.
- Argon2 password authentication.
- Cryptographically signed HttpOnly SameSite session cookies.
- CSRF protection on all state-changing endpoints.
- Multi-tier login rate limiting (Per-IP & Global Tor protection).
- No stack traces or internal server paths exposed.
- No sensitive credentials logged.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import (
    FastAPI,
    Request,
    Response,
    Depends,
    UploadFile,
    File,
    Header,
    HTTPException,
    status
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app import database, security, storage
from app.storage import FileSizeExceededError, StorageError

# Configure secure logging (never log sensitive data)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("oniondrop")

CSRF_PREAUTH_COOKIE = "oniondrop_preauth_csrf"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Ensure directories exist
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    settings.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    database.init_db(settings.DATABASE_PATH)
    logger.info("Database initialized at %s", settings.DATABASE_PATH)
    logger.info("Upload storage initialized at %s (outside web root)", settings.UPLOAD_DIR)
    
    yield
    
    logger.info("OnionDrop shutting down gracefully.")


app = FastAPI(
    title="OnionDrop",
    description="Secure Tor-hosted file drop",
    version="1.0.0",
    docs_url=None,       # Disable Swagger UI documentation
    redoc_url=None,      # Disable ReDoc documentation
    openapi_url=None,    # Disable OpenAPI JSON schema
    lifespan=lifespan
)


# -----------------------------------------------------------------------------
# Security Headers Middleware
# -----------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        # Strip or override server banner
        response.headers["Server"] = "OnionDrop"
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Mount static directory (strictly for CSS and JS, NEVER for uploads)
static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# -----------------------------------------------------------------------------
# Global Safe Exception Handlers (Never expose internal paths or stack traces)
# -----------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    headers = exc.headers or {}
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Sanitize validation errors to avoid internal schema leakage
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Invalid request parameters."}
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log securely on server side, return generic message to client
    logger.error("Internal application error: %s", type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred."}
    )


# -----------------------------------------------------------------------------
# Authentication & CSRF Dependencies
# -----------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    """Extract client IP address."""
    if request.client:
        return request.client.host
    return "127.0.0.1"


def get_current_session(request: Request) -> Optional[dict]:
    """Extract and validate the signed session cookie."""
    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    if not cookie_token:
        return None
    return security.validate_session_token(cookie_token)


def require_authenticated_session(
    request: Request,
    session: Optional[dict] = Depends(get_current_session)
) -> dict:
    """Dependency that mandates a valid authenticated session."""
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required."
        )
    return session


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.get("/health")
@app.head("/health")
async def health_check():
    """Health check endpoint for Docker container monitoring."""
    return {"status": "healthy"}


@app.get("/api/csrf-token")
async def get_csrf_token(
    request: Request,
    response: Response,
    session: Optional[dict] = Depends(get_current_session)
):
    """Retrieve an appropriate CSRF token for the current session or pre-auth state."""
    if session and "csrf_token" in session:
        return {"csrf_token": session["csrf_token"], "authenticated": True}
    
    # Pre-auth CSRF token
    existing_cookie = request.cookies.get(CSRF_PREAUTH_COOKIE)
    if existing_cookie:
        csrf_token = existing_cookie
    else:
        import secrets
        csrf_token = secrets.token_urlsafe(32)
        response.set_cookie(
            key=CSRF_PREAUTH_COOKIE,
            value=csrf_token,
            httponly=False,  # JavaScript must read it to pass in header
            samesite="lax",
            secure=settings.COOKIE_SECURE,
            max_age=3600
        )
    
    return {"csrf_token": csrf_token, "authenticated": False}


@app.get("/api/session")
async def get_session_info(
    request: Request,
    response: Response,
    session: Optional[dict] = Depends(get_current_session)
):
    """Return current authentication state and client configuration."""
    if session:
        return {
            "authenticated": True,
            "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
            "csrf_token": session.get("csrf_token")
        }
    
    # If not authenticated, ensure preauth CSRF is set
    csrf_token = request.cookies.get(CSRF_PREAUTH_COOKIE)
    if not csrf_token:
        import secrets
        csrf_token = secrets.token_urlsafe(32)
        response.set_cookie(
            key=CSRF_PREAUTH_COOKIE,
            value=csrf_token,
            httponly=False,
            samesite="lax",
            secure=settings.COOKIE_SECURE,
            max_age=3600
        )
    
    return {
        "authenticated": False,
        "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
        "csrf_token": csrf_token
    }


@app.post("/api/login")
async def login(
    request: Request,
    response: Response,
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token")
):
    """Authenticate with the shared upload password and establish a signed session."""
    client_ip = get_client_ip(request)

    # 1. Rate Limiting Check (IP-based and Global)
    is_limited, retry_after = security.rate_limiter.is_rate_limited(client_ip)
    if is_limited:
        logger.warning("Rate limit exceeded for login attempt from %s", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # 2. Pre-authentication CSRF Verification
    expected_csrf = request.cookies.get(CSRF_PREAUTH_COOKIE)
    if not expected_csrf or not security.constant_time_compare(x_csrf_token, expected_csrf):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token."
        )

    # 3. Parse JSON credentials
    try:
        body = await request.json()
        password = body.get("password", "")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request payload."
        )

    # 4. Verify Password against Argon2 hash
    is_valid = security.verify_password(password, settings.UPLOAD_PASSWORD_HASH)
    if not is_valid:
        security.rate_limiter.record_failure(client_ip)
        # Slow down brute-force attempts intentionally
        await asyncio.sleep(0.5)
        logger.warning("Failed login attempt from %s", client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password."
        )

    # 5. Success: reset failed attempts & issue session
    security.rate_limiter.record_success(client_ip)
    session_token, csrf_token = security.create_session_token()

    # Set HttpOnly, Signed, SameSite session cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=session_token,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        max_age=settings.SESSION_EXPIRE_HOURS * 3600
    )

    # Clean up pre-auth CSRF cookie
    response.delete_cookie(key=CSRF_PREAUTH_COOKIE)

    logger.info("Successful login from %s", client_ip)
    return {
        "status": "authenticated",
        "csrf_token": csrf_token,
        "max_file_size_mb": settings.MAX_FILE_SIZE_MB
    }


@app.post("/api/logout")
async def logout(
    response: Response,
    session: dict = Depends(require_authenticated_session),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token")
):
    """Terminate the active authenticated session."""
    # CSRF Check
    if not security.constant_time_compare(x_csrf_token, session.get("csrf_token")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token."
        )

    response.delete_cookie(key=settings.COOKIE_NAME)
    return {"status": "logged_out"}


@app.post("/api/upload")
async def upload_files(
    files: List[UploadFile] = File(...),
    session: dict = Depends(require_authenticated_session),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token")
):
    """Receive and securely store uploaded files.
    
    Strict guarantees:
    - Files written with random UUID names outside web root.
    - Original filenames only preserved in metadata.
    - Size checked during stream write (cannot bypass via headers).
    - Permissions set to 0o600.
    - Absolutely no download URL returned.
    """
    # 1. CSRF Verification
    if not security.constant_time_compare(x_csrf_token, session.get("csrf_token")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token."
        )

    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided for upload."
        )

    uploaded_summary = []
    
    for upload_file in files:
        try:
            file_uuid, sanitized_name, total_bytes = await storage.save_upload_file(upload_file)
            
            # Record metadata in SQLite
            database.record_upload(
                db_path=settings.DATABASE_PATH,
                file_uuid=file_uuid,
                original_filename=sanitized_name,
                file_size_bytes=total_bytes,
                content_type=upload_file.content_type
            )
            
            uploaded_summary.append({
                "original_filename": sanitized_name,
                "size_bytes": total_bytes
            })
            
            logger.info("Uploaded file stored securely: size=%d bytes", total_bytes)
            
        except FileSizeExceededError as fee:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE if hasattr(status, "HTTP_413_CONTENT_TOO_LARGE") else 413,
                detail=str(fee)
            )
        except StorageError as se:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File storage processing error."
            )
        finally:
            await upload_file.close()

    return {
        "status": "success",
        "count": len(uploaded_summary),
        "files": uploaded_summary
    }


@app.get("/", response_class=HTMLResponse)
@app.head("/")
async def serve_index(
    request: Request,
    response: Response,
    session: Optional[dict] = Depends(get_current_session)
):
    """Serve the primary HTML application."""
    # Ensure pre-auth CSRF is created if unauthenticated
    csrf_token = ""
    if session and "csrf_token" in session:
        csrf_token = session["csrf_token"]
    else:
        existing_cookie = request.cookies.get(CSRF_PREAUTH_COOKIE)
        if existing_cookie:
            csrf_token = existing_cookie
        else:
            import secrets
            csrf_token = secrets.token_urlsafe(32)
            response.set_cookie(
                key=CSRF_PREAUTH_COOKIE,
                value=csrf_token,
                httponly=False,
                samesite="lax",
                secure=settings.COOKIE_SECURE,
                max_age=3600
            )

    template_path = Path(__file__).resolve().parent / "templates" / "index.html"
    html_content = template_path.read_text(encoding="utf-8")
    
    # Inject initial CSRF token into HTML meta tag
    html_content = html_content.replace('__CSRF_TOKEN__', csrf_token)
    return HTMLResponse(content=html_content, headers=response.headers)
