# OnionDrop

OnionDrop is a minimal, hardened, password-protected, Tor-hosted file upload service designed as a secure one-way dead drop.

Authorized users can upload files anonymously over the Tor network. Once uploaded, files are isolated on disk under random UUIDs outside the web root. In accordance with strict operational security principles, OnionDrop contains **zero download endpoints**, **zero file listing endpoints**, and **zero file previews**.

---

## Key Features

- **Frontend**:
  - Minimalist, modern dark-themed interface with cyber/Tor aesthetics.
  - Large drag-and-drop dropzone with keyboard and visual accessibility.
  - "Browse Files" button supporting single and multi-file selection.
  - Multi-file concurrent uploads with real-time individual progress bars (via XHR streaming progress).
  - Toast notifications for success, failure, and security alerts.
  - Password authentication modal with show/hide password toggle.
  - Fully responsive design for mobile, tablet, and desktop viewports.

- **Backend & Security**:
  - **Argon2id Password Hashing**: Passwords verified against standard OWASP-recommended parameters; plaintext passwords are never stored.
  - **Signed Session Cookies**: HttpOnly, SameSite cookies signed with HMAC using `itsdangerous`.
  - **CSRF Defense**: Cryptographic CSRF tokens required on all state-changing operations (`/api/login`, `/api/logout`, `/api/upload`).
  - **Multi-Tier Rate Limiting**:
    - Per-IP rate limiting sliding window.
    - Global rate limiting sliding window (essential for Tor hidden services where incoming traffic shares `127.0.0.1`).
    - Intentional delay on failed authentication attempts to throttle automated brute-force attacks.
  - **UUID Storage Isolation**: Files are saved strictly using `uuid.uuid4().hex` outside the web root (`data/uploads/`) with `0o600` (read/write only, no execution) permissions.
  - **Chunk-Streamed Size Limit Enforcement**: Upload sizes are enforced chunk-by-chunk during write. If a client attempts to bypass limits with falsified headers, the stream terminates immediately and partial chunks are wiped.
  - **Filename Sanitization**: Original filenames are stripped of directory traversal characters (`../`, `\`), null bytes, and control characters, and stored strictly as audit metadata in SQLite.
  - **Zero Exposure**: Absolutely no route exists to retrieve, inspect, or list uploaded files via the web interface.
  - **Sanitized Errors & Hardened Headers**: All exceptions are trapped without exposing internal paths or stack traces. Includes `nosniff`, `DENY` frames, `no-referrer`, and strict `Content-Security-Policy`.

---

## Directory Structure

```
onion-drop/
├── app/
│   ├── config.py              # Environment settings and Pydantic validation
│   ├── database.py            # SQLite metadata schema and insert operations
│   ├── main.py                # FastAPI app, middleware, routes, security headers
│   ├── security.py            # Argon2 verification, session signer, rate limiter
│   ├── storage.py             # Streaming chunk writer, UUID generator, sanitizer
│   ├── static/
│   │   ├── css/style.css      # Dark-themed responsive stylesheet
│   │   └── js/app.js          # Vanilla JS upload manager & progress bars
│   └── templates/
│       └── index.html         # Single-Page Application interface
├── data/
│   ├── db/                    # SQLite persistent storage (bind-mounted)
│   └── uploads/               # Uploaded files stored as UUIDs (bind-mounted)
├── scripts/
│   └── generate_credentials.py# CLI tool to hash passwords and generate secrets
├── tests/
│   ├── conftest.py            # Pytest test fixtures and isolated environments
│   └── test_security.py       # Security test suite (18 test cases)
├── tor/
│   ├── Dockerfile             # Optional lightweight Tor service container
│   ├── torrc                  # Tor hidden service forwarding configuration
│   └── data/                  # Tor hidden service keys and hostname
├── .env.example               # Example environment configuration
├── .gitignore                 # Strict ignore rules for data, keys, and secrets
├── Dockerfile                 # Hardened, non-root Python 3.12 container
├── docker-compose.yml         # Container orchestration with bind mounts
├── requirements.txt           # Python dependencies
└── README.md
```

---

## Quickstart

### 1. Prerequisites
- Docker and Docker Compose (recommended) OR Python 3.12+
- Tor daemon (either host-installed or via the included docker Tor profile)

### 2. Generate Credentials
Generate a secure Argon2id password hash and a session secret key using the included helper script:

```bash
# Interactive prompt (recommended)
python scripts/generate_credentials.py --write-env

# Or generate with an automatic strong random password
python scripts/generate_credentials.py --random-password --write-env
```

This creates or populates your `.env` file with:
```ini
UPLOAD_PASSWORD_HASH='$argon2id$v=19$m=65536,t=3,p=4$...'
SESSION_SECRET='your-random-high-entropy-secret-key-here'
MAX_FILE_SIZE_MB=100
COOKIE_SECURE=false
COOKIE_SAMESITE=lax
SESSION_EXPIRE_HOURS=4
```

> **Note on `COOKIE_SECURE`:**
> Tor `.onion` services provide transport-layer encryption natively without TLS certificates. When accessing OnionDrop over `http://*.onion`, keep `COOKIE_SECURE=false` because browsers reject Secure cookies over non-HTTPS origins. Set `COOKIE_SECURE=true` only if deploying behind an HTTPS reverse proxy.

---

## Deployment

### Option A: Docker Compose with Tor Container (All-in-One)

You can spin up both OnionDrop and an automated Tor Hidden Service with a single command:

```bash
# Start OnionDrop web service and Tor hidden service
docker compose --profile tor up -d
```

View your newly generated `.onion` domain:
```bash
# Linux / macOS
cat tor/data/hostname

# Windows PowerShell
Get-Content tor/data/hostname
```

Copy the `.onion` address into the [Tor Browser](https://www.torproject.org/) to access your dropzone!

### Option B: Docker Compose (Web Only) + Host Tor Daemon

Run OnionDrop listening on `127.0.0.1:8000` on the host:

```bash
docker compose up -d
```

Configure your host's Tor daemon (`/etc/tor/torrc` on Linux):
```torrc
HiddenServiceDir /var/lib/tor/oniondrop_service/
HiddenServicePort 80 127.0.0.1:8000
```

Restart Tor and find your onion address:
```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/oniondrop_service/hostname
```

### Option C: Bare-Metal / Local Development

```bash
# 1. Install dependencies
python -m pip install -r requirements.txt

# 2. Run the application
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

---

## Security Verification & Tests

OnionDrop includes a dedicated security test suite covering:
- Unauthenticated request rejection (HTTP 401).
- CSRF validation on all state-changing endpoints (HTTP 403).
- Brute-force lockout and rate limiting (HTTP 429).
- Single and multi-file uploads with UUID disk isolation.
- Verification that no download endpoints exist (HTTP 404/405).
- Verification that no listing endpoints exist (HTTP 404/405).
- Stream-based file size limit enforcement (HTTP 413) and partial file cleanup.
- Directory traversal and path attack sanitization (`../../etc/passwd`).
- Security response headers (`nosniff`, `DENY`, `no-referrer`, `CSP`).

Run the test suite:
```bash
python -m pytest -v -s
```

---

## Operational Details & Metadata

### Where are uploaded files stored?
Files are stored inside `data/uploads/` (outside the web root).
Each file is named with a 32-character hexadecimal UUID (e.g. `e1a473b6479f4c3cb33a6f1947b68904`) and file permissions are set to `0o600` (`-rw-------`).

### Where is upload metadata recorded?
Metadata is stored in SQLite at `data/db/metadata.db`.
The `uploads` table records:
- `id`: Auto-incrementing primary key
- `file_uuid`: Unique 32-character UUID filename
- `original_filename`: Sanitized original name
- `file_size_bytes`: Integer size in bytes
- `content_type`: MIME type reported during upload
- `uploaded_at`: ISO 8601 UTC timestamp

### Accessing Uploaded Files
Because OnionDrop does not have any web download or listing endpoints, administrators inspect uploaded files directly via the filesystem on the server or host machine:

```bash
# View metadata in SQLite
sqlite3 data/db/metadata.db "SELECT file_uuid, original_filename, file_size_bytes, uploaded_at FROM uploads ORDER BY id DESC;"

# Access the raw file
ls -la data/uploads/
```

---

## License
MIT
