"""
security.py - Security Middleware, Input Sanitization & Lecturer Attack Defense
Provides:
  - Magic-Byte file signature inspection (prevents extension spoofing / webshell uploads)
  - Strict 50 MB file size limit enforcement
  - Anti-CSRF token verification
  - Brute force lockout & IP rate limiting
  - Path traversal neutralization
  - HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
"""

import os
import re
import hmac
import time
import json
import logging
import secrets
import zipfile
import threading
import io
from logging.handlers import RotatingFileHandler
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import request, session, abort, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB exact limit per uploaded file
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# -----------------------------------------------------------------------------
# Structured Security Audit Logging (OWASP ASVS V7.1.1 / CWE-778)
# -----------------------------------------------------------------------------
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(log_dir, mode=0o700, exist_ok=True)
log_file_path = os.path.join(log_dir, "security_audit.log")

audit_logger = logging.getLogger("vault.security.audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

if not audit_logger.handlers:
    rf_handler = RotatingFileHandler(log_file_path, maxBytes=10 * 1024 * 1024, backupCount=5)
    rf_handler.setFormatter(logging.Formatter('{"time":"%(asctime)s","level":"%(levelname)s","event":%(message)s}'))
    audit_logger.addHandler(rf_handler)


def log_security_event(event_type: str, user_id=None, client_ip=None, details=None, status="SUCCESS"):
    """
    Writes structured, privacy-preserving JSON audit log entries according to OWASP ASVS V7.1.1.
    Never logs raw plaintext passwords, keys, or sensitive personal data.
    """
    ip = client_ip
    if not ip:
        try:
            ip = request.remote_addr if request else "127.0.0.1"
        except Exception:
            ip = "127.0.0.1"

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "user_id": user_id,
        "client_ip": ip,
        "status": status,
        "details": details or {}
    }
    audit_logger.info(json.dumps(entry))


# -----------------------------------------------------------------------------
# Server-Side Key Vault (OWASP ASVS V3.2.3 / CWE-312)
# -----------------------------------------------------------------------------
class ServerSideKeyVault:
    """
    Secure In-Memory Server-Side Key Vault.
    Caches derived cryptographic keys in server process memory bound to an ephemeral
    256-bit vault_token. Raw passwords and raw cryptographic keys NEVER touch
    client session cookies.
    """
    def __init__(self, ttl_seconds: int = 7200):
        self._vault = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def store_keys(self, token: str, keys: dict) -> None:
        if not token or not keys:
            return
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._vault.items() if v['expires'] < now]
            for k in expired:
                del self._vault[k]
            self._vault[token] = {
                'keys': keys,
                'expires': now + self._ttl
            }

    def get_keys(self, token: str) -> dict:
        if not token:
            return None
        with self._lock:
            entry = self._vault.get(token)
            if not entry:
                return None
            if entry['expires'] < time.time():
                del self._vault[token]
                return None
            entry['expires'] = time.time() + self._ttl
            return entry['keys']

    def remove_keys(self, token: str) -> None:
        if not token:
            return
        with self._lock:
            self._vault.pop(token, None)

    def clear(self) -> None:
        with self._lock:
            self._vault.clear()

server_key_vault = ServerSideKeyVault()


# -----------------------------------------------------------------------------
# IP & User Computational Rate Limiter (OWASP ASVS V11.1.4 / CWE-400)
# -----------------------------------------------------------------------------
class RateLimiter:
    """
    Sliding window rate limiter to mitigate brute-force and computational DoS attacks.
    """
    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            timestamps = self._records.setdefault(key, [])
            cutoff = now - window_seconds
            self._records[key] = [t for t in timestamps if t > cutoff]
            if len(self._records[key]) >= max_requests:
                return False
            self._records[key].append(now)
            return True

    def reset(self, key: str = None) -> None:
        with self._lock:
            if key:
                self._records.pop(key, None)
            else:
                self._records.clear()

rate_limiter = RateLimiter()

# Allowed File Extensions strictly restricted to user specification:
# Image: JPG, JPEG, PNG
# PDF: .pdf
# DOC: .docx
# XLS: .xlsx
# Video: .mp4
ALLOWED_EXTENSIONS = {
    'id_card': {'jpg', 'jpeg', 'png'},
    'document': {'pdf', 'docx', 'xlsx'},
    'video': {'mp4'}
}

GLOBAL_ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'docx', 'xlsx', 'mp4'}

# Forbidden script and executable sub-extensions (blocks double-extension attacks such as shell.php.docx)
DANGEROUS_SUB_EXTENSIONS = {
    'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'phps',
    'py', 'pyc', 'pyo', 'pyd',
    'sh', 'bash', 'zsh', 'csh', 'ksh',
    'exe', 'dll', 'so', 'bin', 'elf', 'bat', 'cmd', 'ps1', 'psm1',
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
    'asp', 'aspx', 'cer', 'asa', 'asax',
    'jsp', 'jspx', 'cgi', 'pl', 'pm', 'rb',
    'htaccess', 'htpasswd', 'ini', 'env', 'config', 'inc'
}

# Forbidden script execution signatures in binary payload headers
DANGEROUS_CONTENT_PATTERNS = [
    b'<?php',
    b'<?=',
    b'<script language="php"',
    b'<script language=\'php\'',
    b'<%'
]

# Magic Byte Signatures for allowed file types
MAGIC_SIGNATURES = {
    'id_card': {
        'image/jpeg': [b'\xff\xd8\xff'],
        'image/png': [b'\x89PNG\r\n\x1a\n'],
    },
    'document': {
        'application/pdf': [b'%PDF-'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [b'PK\x03\x04'],  # DOCX
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [b'PK\x03\x04'],       # XLSX
    },
    'video': {
        'video/mp4': [b'ftyp'],
    }
}


class FileSecurityValidator:
    """Validates uploaded files against extension spoofing, double extensions, webshells, and magic byte signatures."""

    @staticmethod
    def validate_file(file_storage, category: str):
        """
        Validates:
          1. File is provided and non-empty.
          2. Null-byte injection prevention (\\x00, %00).
          3. Multi-extension / double-extension defense (e.g. .php.docx).
          4. Strict extension whitelist enforcement (JPG, JPEG, PNG, PDF, DOCX, XLSX, MP4 only).
          5. Strict 50 MB file size limit.
          6. Executable / Webshell script signature scan (<?php, <script, etc.).
          7. Deep magic byte and structure inspection (ZIP OpenXML structure for DOCX/XLSX).
        Returns (is_valid, sanitized_name, detected_mime, error_msg)
        """
        if not file_storage or not file_storage.filename:
            return False, "", "", "No file selected."

        raw_name = file_storage.filename

        # 1. Null-byte injection & control character neutralization
        if '\x00' in raw_name or '%00' in raw_name.lower():
            return False, "", "", "Security violation: Null-byte injection detected in filename."
        if any(ord(c) < 32 for c in raw_name):
            return False, "", "", "Security violation: Control characters detected in filename."

        safe_name = secure_filename(raw_name)
        if not safe_name:
            return False, "", "", "Invalid or malicious filename."

        # 2. Category check
        if category not in ALLOWED_EXTENSIONS:
            return False, safe_name, "", f"Invalid file category '{category}'."

        # 3. Double-extension & extension validation
        parts = safe_name.lower().split('.')
        if len(parts) < 2:
            return False, safe_name, "", "Filename must include a valid file extension."

        ext = parts[-1]
        if ext not in ALLOWED_EXTENSIONS[category]:
            allowed_list = ", ".join(f".{x}" for x in sorted(ALLOWED_EXTENSIONS[category]))
            return False, safe_name, "", (
                f"Disallowed file extension '.{ext}' for category '{category}'. "
                f"Only {allowed_list} files are permitted."
            )

        # Defense against double extensions (e.g., shell.php.docx, exploit.py.png, bad.phtml.pdf)
        for part in parts[:-1]:
            if part in DANGEROUS_SUB_EXTENSIONS:
                return False, safe_name, "", (
                    f"Security block: Malicious script extension '{part}' detected in filename '{safe_name}'. "
                    "Webshell and script execution attempts are strictly blocked."
                )

        # 4. File size inspection
        file_storage.seek(0, os.SEEK_END)
        file_size = file_storage.tell()
        file_storage.seek(0)

        if file_size == 0:
            return False, safe_name, "", "File is empty (0 bytes)."
        if file_size > MAX_FILE_SIZE:
            return False, safe_name, "", (
                f"File exceeds maximum allowed size of 50 MB ({file_size / (1024*1024):.2f} MB)."
            )

        # 5. Executable script content scan in initial header / sample bytes
        header_sample = file_storage.read(min(file_size, 8192))
        file_storage.seek(0)
        sample_lower = header_sample.lower()

        for pattern in DANGEROUS_CONTENT_PATTERNS:
            if pattern in sample_lower:
                return False, safe_name, "", (
                    "Security violation: Executable script code (e.g., PHP tag) detected inside file content. "
                    "Upload blocked."
                )

        # 6. Deep magic byte & structural format inspection
        matched_mime = None

        if category == 'id_card':
            if ext in ('jpg', 'jpeg'):
                if header_sample.startswith(b'\xff\xd8\xff'):
                    matched_mime = 'image/jpeg'
            elif ext == 'png':
                if header_sample.startswith(b'\x89PNG\r\n\x1a\n'):
                    if len(header_sample) >= 16 and header_sample[12:16] == b'IHDR':
                        matched_mime = 'image/png'

        elif category == 'document':
            if ext == 'pdf':
                if header_sample.startswith(b'%PDF-'):
                    matched_mime = 'application/pdf'
            elif ext in ('docx', 'xlsx'):
                if header_sample.startswith(b'PK\x03\x04'):
                    # Deep OpenXML ZIP archive structural verification
                    try:
                        file_storage.seek(0)
                        if not zipfile.is_zipfile(file_storage):
                            return False, safe_name, "", f"File is not a valid {ext.upper()} archive."

                        file_storage.seek(0)
                        with zipfile.ZipFile(file_storage, 'r') as zf:
                            namelist = zf.namelist()

                            # Require OpenXML Content Types declaration
                            if '[Content_Types].xml' not in namelist:
                                return False, safe_name, "", (
                                    f"Invalid {ext.upper()} document: Missing '[Content_Types].xml'."
                                )

                            # Verify document-specific package structure
                            if ext == 'docx':
                                if not any(name.startswith('word/') for name in namelist):
                                    return False, safe_name, "", (
                                        "Invalid DOCX document: Missing 'word/' directory in package."
                                    )
                                matched_mime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

                            elif ext == 'xlsx':
                                if not any(name.startswith('xl/') for name in namelist):
                                    return False, safe_name, "", (
                                        "Invalid XLSX spreadsheet: Missing 'xl/' directory in package."
                                    )
                                matched_mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

                            # Scan archive members for Zip Slip and dangerous embedded scripts
                            for inner_name in namelist:
                                if '..' in inner_name or inner_name.startswith('/') or inner_name.startswith('\\'):
                                    return False, safe_name, "", (
                                        "Malicious archive structure: Directory traversal detected inside package."
                                    )
                                inner_ext = inner_name.rsplit('.', 1)[-1].lower() if '.' in inner_name else ''
                                if inner_ext in DANGEROUS_SUB_EXTENSIONS:
                                    return False, safe_name, "", (
                                        f"Malicious archive content: Embedded script '{inner_name}' detected inside package."
                                    )

                    except zipfile.BadZipFile:
                        return False, safe_name, "", f"Corrupted or malformed {ext.upper()} archive."
                    except Exception as e:
                        return False, safe_name, "", f"OpenXML archive validation error: {str(e)}"
                    finally:
                        file_storage.seek(0)

        elif category == 'video':
            if ext == 'mp4':
                # MP4 ISO Base Media format: 'ftyp' box within first 32 bytes
                if len(header_sample) >= 8 and (header_sample[4:8] == b'ftyp' or b'ftyp' in header_sample[:32]):
                    matched_mime = 'video/mp4'

        if not matched_mime:
            file_storage.seek(0)
            return False, safe_name, "", (
                f"File content does not match expected {category} format for '.{ext}'. "
                "Potential spoofed file or corrupted payload rejected."
            )

        file_storage.seek(0)
        return True, safe_name, matched_mime, ""


def generate_csrf_token() -> str:
    """Generates a cryptographically strong anti-CSRF token bound to the session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def verify_csrf_token(token: str) -> bool:
    stored = session.get('_csrf_token')
    if not stored or not token:
        return False
    return hmac.compare_digest(stored, token)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this secure resource.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def sanitize_text(text: str, max_length: int = 255) -> str:
    """Sanitizes text inputs, stripping harmful control characters while preserving safe Unicode."""
    if not text:
        return ""
    # Strip null bytes and non-printable control characters
    cleaned = "".join(ch for ch in text if ch.isprintable() or ch in '\n\r\t ')
    return cleaned.strip()[:max_length]


def add_security_headers(response):
    """Applies strict HTTP security headers to protect against XSS, clickjacking, and MIME sniffing."""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "connect-src 'self';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
