"""File storage module for OnionDrop.

Handles streaming file uploads, UUID filename generation, file size enforcement,
strict filename sanitization, and setting non-executable file permissions.
Files are stored strictly outside the web root.
"""

import os
import re
import uuid
from pathlib import Path
from typing import Tuple
from fastapi import UploadFile

from app.config import settings


class FileSizeExceededError(Exception):
    """Raised when uploaded file exceeds the configured maximum size."""
    pass


class StorageError(Exception):
    """Raised for any unexpected storage processing failure."""
    pass


def sanitize_filename(filename: str) -> str:
    """Sanitize the original filename to prevent directory traversal or control characters.
    
    Preserves original name for metadata purposes only.
    """
    if not filename:
        return "unnamed_upload"

    # Remove any directory path components (handling both POSIX and Windows separators)
    cleaned = re.split(r"[/\\]", filename)[-1].strip()

    # Remove null bytes, control characters, and risky shell characters
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned)

    # Disallow '.' or '..' as standalone filename
    if cleaned in ("", ".", ".."):
        return "unnamed_upload"

    # Truncate length to 255 characters maximum while preserving extension
    if len(cleaned) > 255:
        stem, ext = os.path.splitext(cleaned)
        max_stem_len = 255 - len(ext)
        if max_stem_len > 0:
            cleaned = stem[:max_stem_len] + ext
        else:
            cleaned = cleaned[:255]

    return cleaned or "unnamed_upload"


async def save_upload_file(upload_file: UploadFile) -> Tuple[str, str, int]:
    """Stream and save an uploaded file safely to disk.
    
    Returns:
        (file_uuid, sanitized_original_filename, total_bytes_written)
    
    Raises:
        FileSizeExceededError: If the upload exceeds the configured size limit.
        StorageError: If saving the file fails.
    """
    upload_dir = settings.UPLOAD_DIR
    upload_dir.mkdir(parents=True, exist_ok=True)

    sanitized_name = sanitize_filename(upload_file.filename or "")
    file_uuid = uuid.uuid4().hex
    target_path = upload_dir / file_uuid
    max_bytes = settings.max_file_size_bytes

    total_bytes = 0
    chunk_size = 64 * 1024  # 64 KB chunks

    # Use os.open to strictly set permissions to 0o600 (owner read/write only, no execution)
    # and O_EXCL to prevent overwrites
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    fd = None
    try:
        fd = os.open(str(target_path), flags, 0o600)
        with open(fd, "wb", closefd=True) as dst:
            fd = None  # python file object now owns fd
            while True:
                chunk = await upload_file.read(chunk_size)
                if not chunk:
                    break
                
                chunk_len = len(chunk)
                if total_bytes + chunk_len > max_bytes:
                    raise FileSizeExceededError(
                        f"File size exceeds maximum allowed limit of {settings.MAX_FILE_SIZE_MB} MB."
                    )
                
                dst.write(chunk)
                total_bytes += chunk_len

    except FileSizeExceededError:
        # Immediately clean up partial file on size limit violation
        if target_path.exists():
            try:
                target_path.unlink()
            except OSError:
                pass
        raise

    except Exception as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if target_path.exists():
            try:
                target_path.unlink()
            except OSError:
                pass
        raise StorageError("Failed to store uploaded file.") from exc

    return file_uuid, sanitized_name, total_bytes
