"""Configuration settings for OnionDrop application.

Loads environment variables with robust validation.
"""

from pathlib import Path
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Core required security credentials
    UPLOAD_PASSWORD_HASH: str = Field(
        default="",
        description="Argon2id password hash for upload authorization"
    )
    SESSION_SECRET: str = Field(
        default="",
        description="Cryptographically secure secret key for signing session cookies"
    )

    # File storage configuration
    MAX_FILE_SIZE_MB: int = Field(
        default=100,
        ge=1,
        le=5000,
        description="Maximum allowed file size in Megabytes"
    )
    UPLOAD_DIR: Path = Field(
        default=Path("data/uploads"),
        description="Filesystem directory for uploaded files (strictly outside web root)"
    )
    DATABASE_PATH: Path = Field(
        default=Path("data/db/metadata.db"),
        description="Filesystem path for SQLite database"
    )

    # Session cookie configuration
    COOKIE_NAME: str = Field(
        default="oniondrop_session",
        description="Name of the session cookie"
    )
    # Note on COOKIE_SECURE:
    # Tor Onion Services (.onion) provide end-to-end encryption without TLS/HTTPS.
    # Browsers typically drop 'Secure' cookies over plain http://*.onion unless configured otherwise.
    # Set COOKIE_SECURE=True if hosting OnionDrop behind an HTTPS reverse proxy.
    COOKIE_SECURE: bool = Field(
        default=False,
        description="Set Secure flag on session cookies (True for HTTPS, False for plain Tor Onion)"
    )
    COOKIE_SAMESITE: str = Field(
        default="lax",
        description="SameSite cookie policy: 'lax' or 'strict'"
    )
    SESSION_EXPIRE_HOURS: int = Field(
        default=4,
        ge=1,
        description="Session validity period in hours"
    )

    # Rate limiting configuration (protect against Tor & IP-based brute forcing)
    RATE_LIMIT_LOGIN_MAX_ATTEMPTS: int = Field(
        default=5,
        ge=1,
        description="Max failed login attempts per IP within the window before temporary lockout"
    )
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = Field(
        default=300,
        ge=10,
        description="Sliding window in seconds for IP rate limiting"
    )
    RATE_LIMIT_GLOBAL_MAX_ATTEMPTS: int = Field(
        default=25,
        ge=5,
        description="Max failed login attempts globally across all Tor clients before global slowdown"
    )
    RATE_LIMIT_GLOBAL_WINDOW_SECONDS: int = Field(
        default=300,
        ge=10,
        description="Sliding window in seconds for global rate limiting"
    )

    @field_validator("UPLOAD_PASSWORD_HASH")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        v = v.strip().strip("'\"")
        # Allow empty during setup/testing if overridden dynamically
        if v and not (v.startswith("$argon2id$") or v.startswith("$argon2i$") or v.startswith("$argon2d$")):
            raise ValueError("UPLOAD_PASSWORD_HASH must be a valid Argon2 hash string (e.g. starting with $argon2id$)")
        return v

    @field_validator("SESSION_SECRET")
    @classmethod
    def validate_session_secret(cls, v: str) -> str:
        return v.strip().strip("'\"")

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024


settings = Settings()
