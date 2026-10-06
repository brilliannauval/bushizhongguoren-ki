"""
models.py - Database Models for Secure Multi-Cipher Web Vault
Supports:
  - User authentication with Argon2id and brute-force lockout
  - GDPR (EU) and UU PDP (Indonesia No. 27/2022) personal data encrypted with AES, DES, RC4
  - Multi-file records (ID Card, Documents, Videos up to 50MB) stored in all 3 ciphers
  - Benchmark performance logs
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime,
    ForeignKey, LargeBinary, Float
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

Base = declarative_base()
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    salt = Column(LargeBinary(16), nullable=False)  # Salt for PBKDF2 key derivation
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    private_data = relationship("PrivateData", back_populates="user", uselist=False, cascade="all, delete-orphan")
    files = relationship("FileRecord", back_populates="user", cascade="all, delete-orphan")
    benchmarks = relationship("BenchmarkLog", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str):
        self.password_hash = ph.hash(password)

    def check_password(self, password: str) -> bool:
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False

    def is_locked(self) -> bool:
        if self.locked_until:
            now = datetime.now(timezone.utc)
            # Ensure timezone-aware comparison
            locked = self.locked_until
            if locked.tzinfo is None:
                locked = locked.replace(tzinfo=timezone.utc)
            return now < locked
        return False


class PrivateData(Base):
    """
    Stores GDPR & UU PDP Personal Data in 3 parallel ciphers (AES-128-CBC, DES-CBC, RC4).
    Complies with:
      - GDPR Art. 4 & 9 (General vs Special Category personal data)
      - UU PDP No. 27/2022 Pasal 4 (Data Pribadi Bersifat Umum & Spesifik)
    """
    __tablename__ = 'private_data'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)

    # General Data: Encrypted Blobs + IVs + HMACs (Stored in JSON or structured fields)
    # Stored as serialized JSON containing encrypted hex strings, IVs, and HMACs
    # Format: {"aes": {"ct": "...", "iv": "...", "hmac": "..."}, "des": {...}, "rc4": {...}}
    full_name_enc = Column(Text, nullable=True)
    email_enc = Column(Text, nullable=True)
    phone_enc = Column(Text, nullable=True)
    dob_enc = Column(Text, nullable=True)
    address_enc = Column(Text, nullable=True)

    # Specific / Sensitive Data (UU PDP Pasal 4 ayat 2):
    nik_enc = Column(Text, nullable=True)          # National ID (KTP / NIK)
    health_info_enc = Column(Text, nullable=True)  # Medical/Health status

    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="private_data")


class FileRecord(Base):
    """
    Tracks encrypted files on disk. Every uploaded file (up to 50MB) is encrypted
    and stored in 3 separate files:
      - <uuid>_aes.enc
      - <uuid>_des.enc
      - <uuid>_rc4.enc
    """
    __tablename__ = 'file_records'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    category = Column(String(32), nullable=False)  # 'id_card', 'document', 'video'
    original_filename = Column(String(256), nullable=False)
    mime_type = Column(String(128), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    
    # Storage file paths (relative to uploads root)
    aes_filename = Column(String(64), nullable=False)
    des_filename = Column(String(64), nullable=False)
    rc4_filename = Column(String(64), nullable=False)

    # Metadata for quick benchmark analysis
    aes_size = Column(Integer, nullable=True)
    des_size = Column(Integer, nullable=True)
    rc4_size = Column(Integer, nullable=True)

    aes_entropy = Column(Float, nullable=True)
    des_entropy = Column(Float, nullable=True)
    rc4_entropy = Column(Float, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="files")


class BenchmarkLog(Base):
    """Stores benchmark run results across download iterations."""
    __tablename__ = 'benchmark_logs'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    item_type = Column(String(32), nullable=False)     # 'profile', 'id_card', 'document', 'video'
    file_id = Column(String(36), nullable=True)
    cipher_name = Column(String(16), nullable=False)   # 'aes', 'des', 'rc4'
    iterations = Column(Integer, nullable=False)
    avg_duration_ms = Column(Float, nullable=False)
    min_duration_ms = Column(Float, nullable=False)
    max_duration_ms = Column(Float, nullable=False)
    throughput_mbps = Column(Float, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="benchmarks")


def init_db(db_path: str = "sqlite:///vault.db"):
    engine = create_engine(db_path, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return engine, Session
