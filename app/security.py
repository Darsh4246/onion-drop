"""Security module for OnionDrop.

Handles Argon2 password hashing/verification, cryptographically signed
session cookies, CSRF validation, and IP/global login rate limiting.
"""

import logging
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.config import settings

logger = logging.getLogger("oniondrop.security")

# Argon2 hasher instance
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash password using Argon2id with default parameters."""
    return _hasher.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify password against Argon2 hash with constant-time guarantee."""
    if not password_hash or not plain_password:
        return False
    try:
        return _hasher.verify(password_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as exc:
        # Never leak internal exception details
        logger.warning("Unexpected error during password verification: %s", type(exc).__name__)
        return False


def get_serializer() -> URLSafeTimedSerializer:
    """Obtain session token serializer."""
    secret = settings.SESSION_SECRET or "unconfigured-session-secret-placeholder"
    return URLSafeTimedSerializer(secret_key=secret, salt="oniondrop-session-v1")


def create_session_token() -> Tuple[str, str]:
    """Create a new signed session token and associated CSRF token.
    
    Returns:
        (signed_session_cookie_value, csrf_token)
    """
    csrf_token = secrets.token_urlsafe(32)
    session_payload = {
        "authenticated": True,
        "session_id": secrets.token_hex(16),
        "csrf_token": csrf_token,
        "created_at": int(time.time()),
    }
    serializer = get_serializer()
    cookie_value = serializer.dumps(session_payload)
    return cookie_value, csrf_token


def validate_session_token(token: Optional[str]) -> Optional[dict]:
    """Validate and decode a signed session cookie.
    
    Returns the session payload dict if valid, or None if invalid or expired.
    """
    if not token or not settings.SESSION_SECRET:
        return None
    serializer = get_serializer()
    max_age_seconds = settings.SESSION_EXPIRE_HOURS * 3600
    try:
        data = serializer.loads(token, max_age=max_age_seconds)
        if isinstance(data, dict) and data.get("authenticated") is True and "csrf_token" in data:
            return data
    except (BadSignature, SignatureExpired):
        return None
    except Exception:
        return None
    return None


def constant_time_compare(val1: Optional[str], val2: Optional[str]) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    if val1 is None or val2 is None:
        return False
    return secrets.compare_digest(val1, val2)


class LoginRateLimiter:
    """Thread-safe rate limiter tracking failed attempts per IP and globally.
    
    Provides defense-in-depth against password brute force attacks,
    especially important for Tor hidden services where incoming requests
    may share localhost IP.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_failures: Dict[str, List[float]] = {}
        self._global_failures: List[float] = []

    def _cleanup_old_records(self, now: float) -> None:
        """Remove timestamps older than max window."""
        max_window = max(
            settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
            settings.RATE_LIMIT_GLOBAL_WINDOW_SECONDS
        )
        cutoff = now - max_window

        # Clean global
        self._global_failures = [t for t in self._global_failures if t > cutoff]

        # Clean per-IP
        stale_ips = []
        for ip, times in self._ip_failures.items():
            valid_times = [t for t in times if t > cutoff]
            if valid_times:
                self._ip_failures[ip] = valid_times
            else:
                stale_ips.append(ip)
        for ip in stale_ips:
            del self._ip_failures[ip]

    def is_rate_limited(self, client_ip: str) -> Tuple[bool, int]:
        """Check if client IP or global failure threshold has been exceeded.
        
        Returns:
            (is_limited, retry_after_seconds)
        """
        now = time.time()
        with self._lock:
            self._cleanup_old_records(now)

            # 1. Check Global limit (crucial for Tor hidden services)
            global_window = settings.RATE_LIMIT_GLOBAL_WINDOW_SECONDS
            global_cutoff = now - global_window
            recent_global = [t for t in self._global_failures if t > global_cutoff]
            if len(recent_global) >= settings.RATE_LIMIT_GLOBAL_MAX_ATTEMPTS:
                retry_after = int(global_cutoff + global_window - recent_global[0]) + 1
                return True, max(1, retry_after)

            # 2. Check per-IP limit
            ip_window = settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS
            ip_cutoff = now - ip_window
            recent_ip = [t for t in self._ip_failures.get(client_ip, []) if t > ip_cutoff]
            if len(recent_ip) >= settings.RATE_LIMIT_LOGIN_MAX_ATTEMPTS:
                retry_after = int(ip_cutoff + ip_window - recent_ip[0]) + 1
                return True, max(1, retry_after)

            return False, 0

    def record_failure(self, client_ip: str) -> None:
        """Record a failed login attempt."""
        now = time.time()
        with self._lock:
            self._global_failures.append(now)
            if client_ip not in self._ip_failures:
                self._ip_failures[client_ip] = []
            self._ip_failures[client_ip].append(now)

    def record_success(self, client_ip: str) -> None:
        """Reset failed attempts for client IP on successful login."""
        with self._lock:
            if client_ip in self._ip_failures:
                del self._ip_failures[client_ip]

    def reset_all(self) -> None:
        """Reset all rate limiter state (useful for test harnesses)."""
        with self._lock:
            self._ip_failures.clear()
            self._global_failures.clear()


rate_limiter = LoginRateLimiter()
