"""Pytest configuration and test fixtures for OnionDrop."""

import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import init_db
from app.security import hash_password, rate_limiter

TEST_PASSWORD = "CorrectHorseBatteryStaple123!"


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Set up an isolated temporary environment for each test."""
    temp_dir = Path(tempfile.mkdtemp(prefix="oniondrop_test_"))
    test_upload_dir = temp_dir / "uploads"
    test_db_dir = temp_dir / "db"
    test_db_path = test_db_dir / "test_metadata.db"

    test_upload_dir.mkdir(parents=True, exist_ok=True)
    test_db_dir.mkdir(parents=True, exist_ok=True)

    # Compute valid Argon2 hash
    pw_hash = hash_password(TEST_PASSWORD)

    monkeypatch.setattr(settings, "UPLOAD_PASSWORD_HASH", pw_hash)
    monkeypatch.setattr(settings, "SESSION_SECRET", "super-secret-test-key-of-high-entropy-32-chars-long")
    monkeypatch.setattr(settings, "UPLOAD_DIR", test_upload_dir)
    monkeypatch.setattr(settings, "DATABASE_PATH", test_db_path)
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 2)  # 2 MB for faster testing
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "RATE_LIMIT_GLOBAL_MAX_ATTEMPTS", 5)

    # Initialize test database
    init_db(test_db_path)

    # Reset rate limiter
    rate_limiter.reset_all()

    yield {
        "upload_dir": test_upload_dir,
        "db_path": test_db_path,
        "temp_dir": temp_dir,
        "password": TEST_PASSWORD,
    }

    # Teardown
    shutil.rmtree(temp_dir, ignore_errors=True)
    rate_limiter.reset_all()


@pytest.fixture
def client():
    """Create FastAPI TestClient."""
    from app.main import app
    with TestClient(app) as test_client:
        yield test_client
