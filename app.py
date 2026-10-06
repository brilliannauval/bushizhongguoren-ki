"""
app.py - Main Application for Secure Multi-Cipher Web Vault (AES, DES, RC4)
"""

import os
import io
import re
import json
import time
import math
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, Response, jsonify, abort, stream_with_context
)
from sqlalchemy.orm import scoped_session

from models import init_db, User, PrivateData, FileRecord, BenchmarkLog
from crypto_service import KeyManager, CryptoVaultEngine, AuthenticationError, CryptoError, zeroize_buffer
from security import (
    FileSecurityValidator, generate_csrf_token, verify_csrf_token,
    login_required, sanitize_text, add_security_headers,
    server_key_vault, rate_limiter, log_security_event,
    MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MINUTES, MAX_FILE_SIZE
)

# Enforce secure umask so files default to 0600 and directories to 0700 (SEC-SAST-05 / CWE-732)
os.umask(0o077)

app = Flask(__name__)

# Persistent SECRET_KEY initialization (SEC-SAST-06 / CWE-384 / CWE-330)
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    os.makedirs(app.instance_path, mode=0o700, exist_ok=True)
    key_file = os.path.join(app.instance_path, '.secret_key')
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r') as f:
                secret_key = f.read().strip()
        except OSError:
            secret_key = secrets.token_hex(32)
    else:
        secret_key = secrets.token_hex(32)
        try:
            with open(key_file, 'w') as f:
                f.write(secret_key)
        except OSError:
            pass

app.config['SECRET_KEY'] = secret_key or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB buffer limit for multipart
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True

os.makedirs(app.config['UPLOAD_FOLDER'], mode=0o700, exist_ok=True)

# Database Setup
engine, SessionFactory = init_db("sqlite:///vault.db")
db_session = scoped_session(SessionFactory)

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

# CSRF Context Processor & Hooks
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

@app.before_request
def check_csrf():
    if app.config.get('TESTING'):
        return
    if request.method in ('POST', 'PUT', 'DELETE'):
        # Allow JSON API benchmark endpoint to pass CSRF via header or form
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        if not verify_csrf_token(token):
            log_security_event("CSRF_VIOLATION", user_id=session.get('user_id'), status="BLOCKED")
            if request.is_json:
                return jsonify({'error': 'Invalid or missing CSRF token'}), 403
            flash("Security error: Invalid or expired CSRF token.", "danger")
            return redirect(request.referrer or url_for('dashboard'))

@app.after_request
def apply_security_headers(response):
    return add_security_headers(response)

# Helper: Get derived keys for currently authenticated user
# ASVS V3.2.3: Uses ServerSideKeyVault so raw passwords never touch client cookies
def get_user_keys(user: User) -> dict:
    vault_token = session.get('vault_token')
    keys = server_key_vault.get_keys(vault_token)
    if not keys:
        # Fallback if testing environment or if user_passphrase was supplied in session
        passphrase = session.get('user_passphrase')
        if passphrase:
            keys = KeyManager.derive_keys(passphrase, user.salt)
            if not vault_token:
                vault_token = secrets.token_hex(32)
                session['vault_token'] = vault_token
            server_key_vault.store_keys(vault_token, keys)
            return keys
        abort(401)
    return keys


# =============================================================================
# Authentication Routes
# =============================================================================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/favicon.ico')
def favicon():
    svg_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#00e5ff"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.67-3.13 9.01-7 10.16-3.87-1.15-7-5.49-7-10.16V6.3l7-3.12z"/></svg>'
    return Response(svg_icon, mimetype='image/svg+xml')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = sanitize_text(request.form.get('username', ''), 32)
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
            flash("Username must be 3-32 characters (letters, numbers, and underscores).", "danger")
            return render_template('register.html')

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            flash("Password must be at least 8 characters with 1 uppercase letter and 1 digit.", "danger")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')

        existing = db_session.query(User).filter_by(username=username).first()
        if existing:
            flash("Username already taken. Please choose another.", "danger")
            return render_template('register.html')

        salt = os.urandom(16)
        new_user = User(username=username, salt=salt)
        new_user.set_password(password)
        db_session.add(new_user)
        db_session.commit()

        flash("Registration successful! You can now log in to your secure vault.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        client_ip = request.remote_addr or '127.0.0.1'
        if not app.config.get('TESTING') and not rate_limiter.is_allowed(f"login_{client_ip}", max_requests=10, window_seconds=60):
            log_security_event("LOGIN_RATE_LIMIT_EXCEEDED", client_ip=client_ip, status="BLOCKED")
            flash("Too many login attempts. Please wait 1 minute before trying again.", "danger")
            return render_template('login.html'), 429

        username = sanitize_text(request.form.get('username', ''), 32)
        password = request.form.get('password', '')

        user = db_session.query(User).filter_by(username=username).first()
        if not user:
            log_security_event("AUTH_FAILURE", client_ip=client_ip, details={"username": username}, status="FAILED")
            flash("Invalid credentials.", "danger")
            return render_template('login.html')

        if user.is_locked():
            log_security_event("AUTH_LOCKED_ATTEMPT", user_id=user.id, client_ip=client_ip, details={"username": username}, status="LOCKED")
            flash(f"Account temporarily locked due to excessive failed attempts. Try again later.", "danger")
            return render_template('login.html')

        if not user.check_password(password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                db_session.commit()
                log_security_event("ACCOUNT_LOCKOUT", user_id=user.id, client_ip=client_ip, details={"username": username}, status="LOCKED")
                flash(f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to {MAX_FAILED_ATTEMPTS} failed attempts.", "danger")
                return render_template('login.html')
            db_session.commit()
            remaining = MAX_FAILED_ATTEMPTS - user.failed_login_attempts
            log_security_event("AUTH_FAILURE", user_id=user.id, client_ip=client_ip, details={"username": username, "remaining": remaining}, status="FAILED")
            flash(f"Invalid credentials. {remaining} attempt(s) remaining before lockout.", "danger")
            return render_template('login.html')

        # Login successful
        user.failed_login_attempts = 0
        user.locked_until = None
        db_session.commit()

        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        
        # ASVS V3.2.3: Store keys in server process memory; client gets only random vault_token
        vault_token = secrets.token_hex(32)
        derived_keys = KeyManager.derive_keys(password, user.salt)
        server_key_vault.store_keys(vault_token, derived_keys)
        session['vault_token'] = vault_token
        if app.config.get('TESTING'):
            session['user_passphrase'] = password

        log_security_event("AUTH_SUCCESS", user_id=user.id, client_ip=client_ip, details={"username": username})
        flash(f"Welcome to your Secure Vault, {user.username}!", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    vault_token = session.get('vault_token')
    if vault_token:
        server_key_vault.remove_keys(vault_token)
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('login'))


# =============================================================================
# Dashboard Route
# =============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    user = db_session.get(User, session['user_id'])
    has_profile = user.private_data is not None
    files_count = len(user.files)
    id_card_count = sum(1 for f in user.files if f.category == 'id_card')
    doc_count = sum(1 for f in user.files if f.category == 'document')
    video_count = sum(1 for f in user.files if f.category == 'video')

    return render_template(
        'dashboard.html',
        user=user,
        has_profile=has_profile,
        files_count=files_count,
        id_card_count=id_card_count,
        doc_count=doc_count,
        video_count=video_count
    )


# =============================================================================
# GDPR & UU PDP Personal Data Route
# =============================================================================

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db_session.get(User, session['user_id'])
    keys = get_user_keys(user)

    if request.method == 'POST':
        # Retrieve form data
        raw_fields = {
            'full_name': sanitize_text(request.form.get('full_name', ''), 128),
            'email': sanitize_text(request.form.get('email', ''), 128),
            'phone': sanitize_text(request.form.get('phone', ''), 32),
            'dob': sanitize_text(request.form.get('dob', ''), 32),
            'address': sanitize_text(request.form.get('address', ''), 255),
            'nik': sanitize_text(request.form.get('nik', ''), 32),
            'health_info': sanitize_text(request.form.get('health_info', ''), 255)
        }

        # Encrypt each field with all 3 ciphers: AES, DES, RC4
        encrypted_payloads = {}
        for field_name, val in raw_fields.items():
            val_bytes = val.encode('utf-8')
            field_enc = {}
            for cipher in ['aes', 'des', 'rc4']:
                res = CryptoVaultEngine.encrypt_data(val_bytes, cipher, keys)
                field_enc[cipher] = {
                    'ct': res['ciphertext'].hex(),
                    'iv': res['iv'].hex(),
                    'hmac': res['hmac'].hex(),
                    'duration_ms': res['duration_ms'],
                    'entropy': res['entropy']
                }
            encrypted_payloads[field_name] = json.dumps(field_enc)

        priv = user.private_data
        if not priv:
            priv = PrivateData(user_id=user.id)
            db_session.add(priv)

        priv.full_name_enc = encrypted_payloads['full_name']
        priv.email_enc = encrypted_payloads['email']
        priv.phone_enc = encrypted_payloads['phone']
        priv.dob_enc = encrypted_payloads['dob']
        priv.address_enc = encrypted_payloads['address']
        priv.nik_enc = encrypted_payloads['nik']
        priv.health_info_enc = encrypted_payloads['health_info']

        db_session.commit()
        flash("GDPR / UU PDP Private Data successfully encrypted in AES, DES, and RC4 and stored in database!", "success")
        return redirect(url_for('profile'))

    # GET: Decrypt data for display and prepare technical cipher comparison table
    decrypted_data = {}
    cipher_comparison = {}
    priv = user.private_data

    if priv:
        fields = [
            ('full_name', priv.full_name_enc, 'Full Name (Nama Lengkap)'),
            ('email', priv.email_enc, 'Email Address'),
            ('phone', priv.phone_enc, 'Phone Number (No. Telepon)'),
            ('dob', priv.dob_enc, 'Date of Birth (Tanggal Lahir)'),
            ('address', priv.address_enc, 'Residential Address (Alamat)'),
            ('nik', priv.nik_enc, 'National ID / NIK (Sensitive / Spesifik)'),
            ('health_info', priv.health_info_enc, 'Health Info (Sensitive / Spesifik)')
        ]

        empty_cipher_entry = {'entropy': 0.0, 'iv': '-', 'ct': '[Corrupted]', 'hmac': '-', 'duration_ms': 0.0}

        for key, enc_json, label in fields:
            default_ciphers = {
                'aes': dict(empty_cipher_entry),
                'des': dict(empty_cipher_entry),
                'rc4': dict(empty_cipher_entry)
            }
            if not enc_json:
                cipher_comparison[key] = {
                    'label': label,
                    'ciphers': default_ciphers
                }
                decrypted_data[key] = "[Corrupted Data: Missing Field]"
                continue

            try:
                meta = json.loads(enc_json)
                if not isinstance(meta, dict):
                    raise ValueError("Not a dictionary")
            except Exception:
                cipher_comparison[key] = {
                    'label': label,
                    'ciphers': default_ciphers
                }
                decrypted_data[key] = "[Corrupted Data: Malformed Record]"
                continue

            normalized_ciphers = {}
            for c_name in ['aes', 'des', 'rc4']:
                c_val = meta.get(c_name)
                if isinstance(c_val, dict):
                    normalized_ciphers[c_name] = {
                        'entropy': c_val.get('entropy', 0.0),
                        'iv': c_val.get('iv', '-'),
                        'ct': c_val.get('ct', '[Corrupted]'),
                        'hmac': c_val.get('hmac', '-'),
                        'duration_ms': c_val.get('duration_ms', 0.0)
                    }
                else:
                    normalized_ciphers[c_name] = dict(empty_cipher_entry)

            cipher_comparison[key] = {
                'label': label,
                'ciphers': normalized_ciphers
            }

            try:
                aes_info = normalized_ciphers['aes']
                if aes_info['ct'] == '[Corrupted]' or aes_info['iv'] == '-' or aes_info['hmac'] == '-':
                    decrypted_data[key] = "[Corrupted Data: Malformed Record]"
                else:
                    ct = bytes.fromhex(aes_info['ct'])
                    iv = bytes.fromhex(aes_info['iv'])
                    hmac_val = bytes.fromhex(aes_info['hmac'])
                    plain, _ = CryptoVaultEngine.decrypt_data(ct, 'aes', iv, hmac_val, keys)
                    decrypted_data[key] = plain.decode('utf-8', errors='replace')
            except Exception as e:
                decrypted_data[key] = f"[Decryption Error: {str(e)}]"

    return render_template(
        'profile.html',
        user=user,
        priv=priv,
        decrypted_data=decrypted_data,
        cipher_comparison=cipher_comparison
    )


# =============================================================================
# File Vault Routes (ID Card, Documents, Videos up to 50MB)
# =============================================================================

@app.route('/files')
@login_required
def files():
    user = db_session.get(User, session['user_id'])
    id_cards = [f for f in user.files if f.category == 'id_card']
    documents = [f for f in user.files if f.category == 'document']
    videos = [f for f in user.files if f.category == 'video']

    return render_template(
        'files.html',
        user=user,
        id_cards=id_cards,
        documents=documents,
        videos=videos,
        max_file_size_mb=MAX_FILE_SIZE // (1024 * 1024)
    )


@app.route('/files/upload', methods=['POST'])
@login_required
def upload_file():
    user = db_session.get(User, session['user_id'])
    keys = get_user_keys(user)

    category = request.form.get('category', '').strip().lower()
    if category not in ('id_card', 'document', 'video'):
        flash("Invalid file category.", "danger")
        return redirect(url_for('files'))

    if 'file' not in request.files:
        flash("No file part in request.", "danger")
        return redirect(url_for('files'))

    file_obj = request.files['file']
    is_valid, safe_name, mime_type, err = FileSecurityValidator.validate_file(file_obj, category)
    if not is_valid:
        flash(f"Upload rejected: {err}", "danger")
        return redirect(url_for('files'))

    file_id = str(uuid.uuid4())
    aes_fname = f"{file_id}_aes.enc"
    des_fname = f"{file_id}_des.enc"
    rc4_fname = f"{file_id}_rc4.enc"

    aes_path = os.path.join(app.config['UPLOAD_FOLDER'], aes_fname)
    des_path = os.path.join(app.config['UPLOAD_FOLDER'], des_fname)
    rc4_path = os.path.join(app.config['UPLOAD_FOLDER'], rc4_fname)

    created_paths = [aes_path, des_path, rc4_path]

    try:
        # Encrypt in all 3 ciphers simultaneously
        # File pointer must be rewound before each pass
        file_obj.seek(0)
        aes_meta = CryptoVaultEngine.encrypt_file_stream(file_obj, aes_path, 'aes', keys)

        file_obj.seek(0)
        des_meta = CryptoVaultEngine.encrypt_file_stream(file_obj, des_path, 'des', keys)

        file_obj.seek(0)
        rc4_meta = CryptoVaultEngine.encrypt_file_stream(file_obj, rc4_path, 'rc4', keys)

        file_obj.seek(0, os.SEEK_END)
        orig_size = file_obj.tell()

        record = FileRecord(
            id=file_id,
            user_id=user.id,
            category=category,
            original_filename=safe_name,
            mime_type=mime_type,
            file_size_bytes=orig_size,
            aes_filename=aes_fname,
            des_filename=des_fname,
            rc4_filename=rc4_fname,
            aes_size=aes_meta['total_stored_size'],
            des_size=des_meta['total_stored_size'],
            rc4_size=rc4_meta['total_stored_size'],
            aes_entropy=aes_meta['entropy'],
            des_entropy=des_meta['entropy'],
            rc4_entropy=rc4_meta['entropy']
        )
        db_session.add(record)
        db_session.commit()

        log_security_event("FILE_UPLOAD", user_id=user.id, details={"filename": safe_name, "category": category, "file_id": file_id, "size": orig_size})
        flash(
            f"File '{safe_name}' ({orig_size / (1024*1024):.2f} MB) successfully encrypted in AES, DES, and RC4!",
            "success"
        )
        return redirect(url_for('files'))

    except PermissionError as pe:
        db_session.rollback()
        for p in created_paths:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
            if os.path.exists(p + ".tmp"):
                try:
                    os.remove(p + ".tmp")
                except OSError:
                    pass
        app.logger.error("Storage permission error during upload: %s", str(pe))
        log_security_event("STORAGE_PERMISSION_ERROR", user_id=user.id, status="ERROR")
        flash("Storage error: Upload directory permission denied. Please contact system administrator.", "danger")
        return redirect(url_for('files'))

    except Exception as e:
        db_session.rollback()
        for p in created_paths:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
            if os.path.exists(p + ".tmp"):
                try:
                    os.remove(p + ".tmp")
                except OSError:
                    pass
        app.logger.error("Error during multi-cipher file encryption: %s", str(e), exc_info=True)
        log_security_event("FILE_UPLOAD_FAILED", user_id=user.id, details={"error": str(e)}, status="ERROR")
        flash("Upload failed: An error occurred during encryption processing.", "danger")
        return redirect(url_for('files'))


@app.route('/files/download/<file_id>')
@login_required
def download_file(file_id):
    user = db_session.get(User, session['user_id'])
    keys = get_user_keys(user)
    cipher_name = request.args.get('cipher', 'aes').lower()

    if cipher_name not in ('aes', 'des', 'rc4'):
        abort(400, "Invalid cipher selection.")

    record = db_session.query(FileRecord).filter_by(id=file_id, user_id=user.id).first()
    if not record:
        abort(404, "File not found or permission denied (IDOR protection).")

    filename_map = {
        'aes': record.aes_filename,
        'des': record.des_filename,
        'rc4': record.rc4_filename
    }
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], filename_map[cipher_name])
    if not os.path.exists(enc_path):
        abort(404, "Encrypted vault file not found on disk.")

    try:
        def stream_decrypt():
            for chunk in CryptoVaultEngine.decrypt_file_stream(enc_path, cipher_name, keys):
                yield chunk

        response = Response(stream_with_context(stream_decrypt()), mimetype=record.mime_type)
        response.headers['Content-Disposition'] = f'attachment; filename="{record.original_filename}"'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Decryption-Cipher'] = cipher_name.upper()
        return response

    except AuthenticationError:
        log_security_event("HMAC_TAMPER_DETECTED", user_id=user.id, details={"file_id": file_id, "cipher": cipher_name}, status="ALERT")
        abort(403, "Tampering detected: HMAC verification failed.")
    except Exception as e:
        app.logger.error("Decryption streaming error: %s", str(e), exc_info=True)
        abort(500, "An internal error occurred during secure file decryption.")


@app.route('/files/preview/<file_id>')
@login_required
def preview_file(file_id):
    """Allows in-browser preview of decrypted images and MP4 videos."""
    user = db_session.get(User, session['user_id'])
    keys = get_user_keys(user)
    cipher_name = request.args.get('cipher', 'aes').lower()

    if cipher_name not in ('aes', 'des', 'rc4'):
        cipher_name = 'aes'

    record = db_session.query(FileRecord).filter_by(id=file_id, user_id=user.id).first()
    if not record:
        abort(404)

    # In-browser preview restricted strictly to images and MP4
    if record.mime_type not in ('image/jpeg', 'image/png', 'video/mp4'):
        abort(403, "Direct in-browser preview is restricted to JPG, PNG, and MP4 media. Please use Decrypted Download.")

    filename_map = {'aes': record.aes_filename, 'des': record.des_filename, 'rc4': record.rc4_filename}
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], filename_map[cipher_name])

    try:
        def stream_decrypt():
            for chunk in CryptoVaultEngine.decrypt_file_stream(enc_path, cipher_name, keys):
                yield chunk

        response = Response(stream_with_context(stream_decrypt()), mimetype=record.mime_type)
        response.headers['Content-Disposition'] = f'inline; filename="{record.original_filename}"'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    except AuthenticationError:
        log_security_event("HMAC_TAMPER_DETECTED", user_id=user.id, details={"file_id": file_id, "cipher": cipher_name}, status="ALERT")
        abort(403, "Tampering detected: HMAC verification failed.")
    except Exception as e:
        app.logger.error("Preview decryption stream error: %s", str(e), exc_info=True)
        abort(500, "An internal error occurred during file preview.")


@app.route('/files/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    user = db_session.get(User, session['user_id'])
    record = db_session.query(FileRecord).filter_by(id=file_id, user_id=user.id).first()
    if not record:
        abort(404)

    for fname in [record.aes_filename, record.des_filename, record.rc4_filename]:
        fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
            except OSError:
                pass

    db_session.delete(record)
    db_session.commit()
    log_security_event("VAULT_FILE_DELETE", user_id=user.id, details={"file_id": file_id, "filename": record.original_filename})
    flash("File securely deleted from vault.", "info")
    return redirect(url_for('files'))


# =============================================================================
# Benchmarking Routes (Empirical Comparison & Multiple Downloads)
# =============================================================================

@app.route('/benchmark')
@login_required
def benchmark():
    user = db_session.get(User, session['user_id'])
    files_list = user.files
    logs = db_session.query(BenchmarkLog).filter_by(user_id=user.id).order_by(BenchmarkLog.created_at.desc()).limit(20).all()
    return render_template('benchmark.html', user=user, files=files_list, logs=logs)


@app.route('/api/benchmark/run', methods=['POST'])
@login_required
def api_run_benchmark():
    """
    Executes multiple download/decryption iterations for AES, DES, and RC4.
    Measures:
      - Running time per iteration (ms)
      - Mean, Min, Max, and Standard Deviation
      - Throughput (MB/s)
      - Shannon Entropy & Ciphertext Size
    """
    user = db_session.get(User, session['user_id'])
    keys = get_user_keys(user)

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
    if not app.config.get('TESTING') and not rate_limiter.is_allowed(f"bench_{user.id}", max_requests=10, window_seconds=60):
        log_security_event("RATE_LIMIT_EXCEEDED", user_id=user.id, client_ip=client_ip, details={"endpoint": "/api/benchmark/run"}, status="ALERT")
        return jsonify({'error': 'Rate limit exceeded. Please wait before running another benchmark.'}), 429

    data = request.get_json() or {}
    item_type = data.get('item_type', 'file')
    file_id = data.get('file_id')
    iterations = int(data.get('iterations', 5))
    iterations = max(1, min(iterations, 20))  # Bound between 1 and 20

    if item_type == 'profile':
        priv = user.private_data
        if not priv:
            return jsonify({'error': 'No private profile data found to benchmark.'}), 400

        meta = json.loads(priv.full_name_enc)
        results = {}

        for cipher in ['aes', 'des', 'rc4']:
            ct = bytes.fromhex(meta[cipher]['ct'])
            iv = bytes.fromhex(meta[cipher]['iv'])
            hmac_val = bytes.fromhex(meta[cipher]['hmac'])
            durations = []

            for _ in range(iterations):
                t0 = time.perf_counter()
                CryptoVaultEngine.decrypt_data(ct, cipher, iv, hmac_val, keys)
                durations.append((time.perf_counter() - t0) * 1000.0)

            avg_d = sum(durations) / len(durations)
            min_d = min(durations)
            max_d = max(durations)
            variance = sum((x - avg_d) ** 2 for x in durations) / len(durations)
            std_dev = math.sqrt(variance)

            results[cipher] = {
                'durations': [round(d, 4) for d in durations],
                'avg_ms': round(avg_d, 4),
                'min_ms': round(min_d, 4),
                'max_ms': round(max_d, 4),
                'std_dev': round(std_dev, 4),
                'ciphertext_size': len(ct),
                'entropy': meta[cipher]['entropy'],
                'throughput_mbps': round((len(ct) / (1024 * 1024)) / (avg_d / 1000.0), 2) if avg_d > 0 else 0
            }

        return jsonify({'item': 'GDPR Profile Data', 'iterations': iterations, 'results': results})

    elif item_type == 'file':
        if not file_id:
            return jsonify({'error': 'file_id required'}), 400

        record = db_session.query(FileRecord).filter_by(id=file_id, user_id=user.id).first()
        if not record:
            return jsonify({'error': 'File not found'}), 404

        file_map = {
            'aes': (record.aes_filename, record.aes_size, record.aes_entropy),
            'des': (record.des_filename, record.des_size, record.des_entropy),
            'rc4': (record.rc4_filename, record.rc4_size, record.rc4_entropy)
        }

        results = {}

        for cipher, (fname, size, entropy) in file_map.items():
            enc_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            if not os.path.exists(enc_path):
                continue

            durations = []

            for _ in range(iterations):
                t0 = time.perf_counter()
                # Stream entire file decryption
                for _ in CryptoVaultEngine.decrypt_file_stream(enc_path, cipher, keys):
                    pass
                durations.append((time.perf_counter() - t0) * 1000.0)

            avg_d = sum(durations) / len(durations)
            min_d = min(durations)
            max_d = max(durations)
            variance = sum((x - avg_d) ** 2 for x in durations) / len(durations)
            std_dev = math.sqrt(variance)
            throughput = (record.file_size_bytes / (1024 * 1024)) / (avg_d / 1000.0) if avg_d > 0 else 0

            results[cipher] = {
                'durations': [round(d, 2) for d in durations],
                'avg_ms': round(avg_d, 2),
                'min_ms': round(min_d, 2),
                'max_ms': round(max_d, 2),
                'std_dev': round(std_dev, 2),
                'ciphertext_size': size,
                'entropy': entropy,
                'throughput_mbps': round(throughput, 2)
            }

            # Save to BenchmarkLog
            log_entry = BenchmarkLog(
                user_id=user.id,
                item_type=record.category,
                file_id=record.id,
                cipher_name=cipher,
                iterations=iterations,
                avg_duration_ms=avg_d,
                min_duration_ms=min_d,
                max_duration_ms=max_d,
                throughput_mbps=throughput
            )
            db_session.add(log_entry)

        db_session.commit()

        return jsonify({
            'item': f"{record.original_filename} ({record.file_size_bytes / (1024*1024):.2f} MB)",
            'iterations': iterations,
            'results': results
        })

    return jsonify({'error': 'Invalid item_type'}), 400


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(429)
@app.errorhandler(500)
def handle_http_errors(error):
    code = getattr(error, 'code', 500)
    description = "An internal error occurred." if code == 500 else getattr(error, 'description', 'Request Error')
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': description, 'code': code}), code
    return render_template('error.html', code=code, description=description), code


if __name__ == '__main__':
    bind_host = os.environ.get('VAULT_HOST', '127.0.0.1')
    bind_port = int(os.environ.get('VAULT_PORT', 5000))
    app.run(host=bind_host, port=bind_port, debug=False)
