"""Security and functional test suite for OnionDrop.

Verifies:
- Unauthenticated access rejections.
- CSRF validation across state-changing endpoints.
- Rate limiting against brute-force password guessing.
- File storage isolation outside web root with UUID naming.
- Zero download and zero file-listing endpoints.
- Chunk-streamed file size limit enforcement and cleanup.
- Malicious filename sanitization and traversal prevention.
- Security headers and error sanitization.
"""

import io
import os
import sqlite3
import pytest
from app.config import settings


def get_preauth_csrf(client):
    """Helper to fetch pre-auth CSRF token and set cookie."""
    resp = client.get("/api/csrf-token")
    assert resp.status_code == 200
    token = resp.json()["csrf_token"]
    assert token
    return token


def login_helper(client, password):
    """Helper to perform full login flow returning csrf_token."""
    csrf_token = get_preauth_csrf(client)
    resp = client.post(
        "/api/login",
        json={"password": password},
        headers={"X-CSRF-Token": csrf_token}
    )
    return resp


class TestHealthAndStatic:
    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "healthy"}

    def test_security_headers_present(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "no-referrer"
        assert "Content-Security-Policy" in resp.headers
        assert resp.headers.get("Server") == "OnionDrop"

    def test_static_directory_does_not_list(self, client):
        # Attempting directory listing on /static/
        resp = client.get("/static/")
        assert resp.status_code in (404, 403)


class TestAuthenticationAndCSRF:
    def test_login_missing_csrf_fails(self, client, setup_test_environment):
        resp = client.post("/api/login", json={"password": setup_test_environment["password"]})
        assert resp.status_code == 403
        assert "CSRF" in resp.json().get("detail", "")

    def test_login_invalid_csrf_fails(self, client, setup_test_environment):
        get_preauth_csrf(client)
        resp = client.post(
            "/api/login",
            json={"password": setup_test_environment["password"]},
            headers={"X-CSRF-Token": "invalid-csrf-token"}
        )
        assert resp.status_code == 403

    def test_login_invalid_password_fails(self, client):
        resp = login_helper(client, "WrongPassword!")
        assert resp.status_code == 401
        assert "Invalid password" in resp.json().get("detail", "")

    def test_login_success(self, client, setup_test_environment):
        resp = login_helper(client, setup_test_environment["password"])
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "authenticated"
        assert "csrf_token" in data

        # Check HttpOnly session cookie
        cookies = client.cookies
        assert settings.COOKIE_NAME in cookies

    def test_logout_invalidates_session(self, client, setup_test_environment):
        login_resp = login_helper(client, setup_test_environment["password"])
        assert login_resp.status_code == 200
        csrf_token = login_resp.json()["csrf_token"]

        # Logout with CSRF
        logout_resp = client.post("/api/logout", headers={"X-CSRF-Token": csrf_token})
        assert logout_resp.status_code == 200

        # Session should now be terminated
        session_resp = client.get("/api/session")
        assert session_resp.json()["authenticated"] is False


class TestRateLimiting:
    def test_login_rate_limiting_lockout(self, client):
        """Verify that repeated invalid attempts trigger 429 Too Many Requests."""
        max_attempts = settings.RATE_LIMIT_LOGIN_MAX_ATTEMPTS  # 3 in fixture
        
        for _ in range(max_attempts):
            csrf = get_preauth_csrf(client)
            resp = client.post(
                "/api/login",
                json={"password": "bad_guess"},
                headers={"X-CSRF-Token": csrf}
            )
            assert resp.status_code == 401

        # The next attempt must be rate-limited
        csrf = get_preauth_csrf(client)
        blocked_resp = client.post(
            "/api/login",
            json={"password": "bad_guess"},
            headers={"X-CSRF-Token": csrf}
        )
        assert blocked_resp.status_code == 429
        assert "Too many failed attempts" in blocked_resp.json().get("detail", "")
        assert "Retry-After" in blocked_resp.headers


class TestUploadSecurity:
    def test_unauthenticated_upload_fails(self, client):
        """Unauthenticated uploads must strictly be rejected with 401."""
        test_file = io.BytesIO(b"Hello secure onion drop")
        resp = client.post(
            "/api/upload",
            files={"files": ("test.txt", test_file, "text/plain")},
            headers={"X-CSRF-Token": "some-token"}
        )
        assert resp.status_code == 401
        assert "Authentication required" in resp.json().get("detail", "")

    def test_upload_missing_csrf_fails(self, client, setup_test_environment):
        """Authenticated upload without valid CSRF must fail with 403."""
        login_helper(client, setup_test_environment["password"])
        
        test_file = io.BytesIO(b"Confidential data payload")
        resp = client.post(
            "/api/upload",
            files={"files": ("leak.txt", test_file, "text/plain")},
            # Missing X-CSRF-Token
        )
        assert resp.status_code == 403

    def test_successful_authenticated_upload(self, client, setup_test_environment):
        """Upload succeeds, file stored as UUID, metadata recorded in SQLite."""
        login_resp = login_helper(client, setup_test_environment["password"])
        csrf_token = login_resp.json()["csrf_token"]

        content = b"Encrypted whistleblower document contents"
        file_payload = io.BytesIO(content)
        original_name = "whistleblower_report.pdf"

        resp = client.post(
            "/api/upload",
            files={"files": (original_name, file_payload, "application/pdf")},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["count"] == 1
        assert data["files"][0]["original_filename"] == original_name
        assert data["files"][0]["size_bytes"] == len(content)

        # Verify disk storage: file must exist as UUID, NOT as original name
        upload_dir = setup_test_environment["upload_dir"]
        stored_files = list(upload_dir.glob("*"))
        # Exclude .gitkeep
        stored_files = [f for f in stored_files if f.name != ".gitkeep"]
        assert len(stored_files) == 1

        stored_file = stored_files[0]
        # UUID is 32 hex characters
        assert len(stored_file.name) == 32
        assert stored_file.name != original_name
        assert stored_file.read_bytes() == content

        # Verify SQLite metadata
        db_path = setup_test_environment["db_path"]
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT file_uuid, original_filename, file_size_bytes FROM uploads")
        rows = cursor.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == stored_file.name
        assert rows[0][1] == original_name
        assert rows[0][2] == len(content)
        conn.close()

    def test_file_size_limit_enforced_and_purged(self, client, setup_test_environment):
        """Files exceeding configured size must fail with 413 and leave no partial files."""
        login_resp = login_helper(client, setup_test_environment["password"])
        csrf_token = login_resp.json()["csrf_token"]

        # Fixture configured MAX_FILE_SIZE_MB = 2 MB
        max_bytes = 2 * 1024 * 1024
        oversized_content = b"X" * (max_bytes + 1024)  # Exceeds limit by 1 KB
        oversized_file = io.BytesIO(oversized_content)

        resp = client.post(
            "/api/upload",
            files={"files": ("large_video.mp4", oversized_file, "video/mp4")},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert resp.status_code == 413
        assert "exceeds maximum allowed limit" in resp.json().get("detail", "")

        # Verify no partial file was left on disk
        upload_dir = setup_test_environment["upload_dir"]
        stored_files = [f for f in upload_dir.glob("*") if f.name != ".gitkeep"]
        assert len(stored_files) == 0

    def test_path_traversal_filename_sanitization(self, client, setup_test_environment):
        """Attacks with directory traversal or null bytes in filename must be sanitized."""
        login_resp = login_helper(client, setup_test_environment["password"])
        csrf_token = login_resp.json()["csrf_token"]

        malicious_filename = "../../../../etc/passwd"
        content = b"root:x:0:0:root:/root:/bin/bash"

        resp = client.post(
            "/api/upload",
            files={"files": (malicious_filename, io.BytesIO(content), "text/plain")},
            headers={"X-CSRF-Token": csrf_token}
        )
        assert resp.status_code == 200
        stored_meta_name = resp.json()["files"][0]["original_filename"]
        # Must strip path components
        assert stored_meta_name == "passwd"
        assert "/" not in stored_meta_name
        assert ".." not in stored_meta_name

        # Verify on disk
        upload_dir = setup_test_environment["upload_dir"]
        stored_files = [f for f in upload_dir.glob("*") if f.name != ".gitkeep"]
        assert len(stored_files) == 1
        assert len(stored_files[0].name) == 32  # Stored by UUID only

    def test_multiple_simultaneous_file_uploads(self, client, setup_test_environment):
        """Verify uploading multiple files simultaneously in one request."""
        login_resp = login_helper(client, setup_test_environment["password"])
        csrf_token = login_resp.json()["csrf_token"]

        f1 = ("doc1.txt", io.BytesIO(b"Document 1 contents"), "text/plain")
        f2 = ("doc2.txt", io.BytesIO(b"Document 2 contents"), "text/plain")
        f3 = ("image.png", io.BytesIO(b"\x89PNG\r\n\x1a\nFakePNG"), "image/png")

        resp = client.post(
            "/api/upload",
            files=[("files", f1), ("files", f2), ("files", f3)],
            headers={"X-CSRF-Token": csrf_token}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["count"] == 3
        assert len(data["files"]) == 3

        # Verify all 3 stored on disk
        upload_dir = setup_test_environment["upload_dir"]
        stored_files = [f for f in upload_dir.glob("*") if f.name != ".gitkeep"]
        assert len(stored_files) == 3


class TestStrictZeroExposure:
    """Strictly verify that NO download, preview, or listing endpoints exist."""

    def test_no_download_endpoints(self, client):
        uuid_dummy = "4f8a3b5c6d7e8f9012345678abcdef01"
        forbidden_endpoints = [
            f"/download/{uuid_dummy}",
            f"/downloads/{uuid_dummy}",
            f"/files/{uuid_dummy}",
            f"/uploads/{uuid_dummy}",
            f"/data/{uuid_dummy}",
            f"/data/uploads/{uuid_dummy}",
            f"/raw/{uuid_dummy}",
            f"/preview/{uuid_dummy}",
            f"/view/{uuid_dummy}",
        ]
        for url in forbidden_endpoints:
            resp = client.get(url)
            assert resp.status_code in (404, 405), f"Endpoint {url} returned {resp.status_code} instead of 404/405"

    def test_no_listing_endpoints(self, client):
        listing_endpoints = [
            "/list",
            "/files",
            "/uploads",
            "/api/files",
            "/api/list",
            "/api/uploads",
            "/metadata",
        ]
        for url in listing_endpoints:
            resp = client.get(url)
            assert resp.status_code in (404, 405), f"Endpoint {url} returned {resp.status_code} instead of 404/405"

    def test_path_traversal_on_static_blocked(self, client):
        """Ensure static files mount cannot traverse into data or app root."""
        traversal_attempts = [
            "/static/../data/uploads",
            "/static/..%2f..%2fdata%2fuploads",
            "/static/../main.py",
            "/static/../config.py",
        ]
        for url in traversal_attempts:
            resp = client.get(url)
            assert resp.status_code in (404, 400), f"Static traversal {url} returned {resp.status_code}"
