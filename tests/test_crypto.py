from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from securebox.crypto import CryptoProvider, CryptoStatus, NativeCryptoFault
from securebox.envelope import EnvelopeError, open_payload, seal_payload, variant_aad


def test_gcm_envelope_authenticates_payload_and_context():
    kek = b"k" * 32
    sealed, wrapped = seal_payload(b"private", kek, b"owner:item:aes:v1")
    assert open_payload(sealed, wrapped, kek, b"owner:item:aes:v1") == b"private"
    with pytest.raises(EnvelopeError):
        open_payload(sealed, wrapped, kek, b"other-owner:item:aes:v1")
    damaged = sealed[:-1] + bytes([sealed[-1] ^ 1])
    with pytest.raises(EnvelopeError):
        open_payload(damaged, wrapped, kek, b"owner:item:aes:v1")


def test_variant_envelope_binds_mode_crypto_and_envelope_versions():
    kek = b"k" * 32
    aad = variant_aad("owner", "item", "aes", "AES-128-CBC/PKCS7", "securebox-crypto-v1")
    sealed, wrapped = seal_payload(b"ciphertext and inner key bundle", kek, aad)
    assert open_payload(sealed, wrapped, kek, aad) == b"ciphertext and inner key bundle"
    for changed in (
        variant_aad("owner", "item", "aes", "AES-128-CBC", "securebox-crypto-v1"),
        variant_aad("owner", "item", "aes", "AES-128-CBC/PKCS7", "securebox-crypto-v2"),
        variant_aad("owner", "item", "aes", "AES-128-CBC/PKCS7", "securebox-crypto-v1", "gcm-a256-v2"),
    ):
        with pytest.raises(EnvelopeError):
            open_payload(sealed, wrapped, kek, changed)


@pytest.mark.parametrize("algorithm", ["aes", "des", "rc4"])
def test_each_cipher_roundtrips_exact_binary_data(algorithm):
    provider = CryptoProvider()
    result = provider.make_variant(algorithm, b"\x00binary\xff payload\n")
    restored, _ = provider.decrypt(algorithm, result["ciphertext"], result["key"], result["iv"], result["backend"])
    assert restored == b"\x00binary\xff payload\n"
    assert result["backend"] in {"x86_64-assembly", "pycryptodome"}


def test_python_fallback_is_explicitly_labeled():
    provider = CryptoProvider()
    provider._status = CryptoStatus("pycryptodome", False, "test_native_unavailable")
    result = provider.make_variant("aes", b"fallback vector")
    assert result["backend"] == "pycryptodome"
    restored, _ = provider.decrypt("aes", result["ciphertext"], result["key"], result["iv"], "pycryptodome")
    assert restored == b"fallback vector"


def test_supplied_assembly_known_answer_vectors_pass_when_built():
    library = Path("securebox/crypto_asm/libcrypto_asm.so")
    if not library.exists():
        pytest.skip("Native library was not built on this target")
    result = subprocess.run([sys.executable, "-m", "securebox.crypto_worker", "--kat"], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout.decode(errors="replace")
    assert b'"ok":true' in result.stdout


def test_native_process_fault_quarantines_and_uses_labeled_python_fallback(monkeypatch):
    import json
    import struct

    provider = CryptoProvider()
    provider._status = CryptoStatus("x86_64-assembly", True, "test")
    actual_run = subprocess.run

    def native_crash_python_works(*args, **kwargs):
        frame = kwargs.get("input", b"")
        header_size = struct.unpack(">I", frame[:4])[0]
        header = json.loads(frame[4 : 4 + header_size])
        if header["backend"] == "asm":
            class Failed:
                returncode = -11
                stdout = b""

            return Failed()
        return actual_run(*args, **kwargs)

    monkeypatch.setattr("securebox.crypto.subprocess.run", native_crash_python_works)
    result = provider.make_variant("aes", b"runtime fallback vector")
    restored, _ = provider.decrypt("aes", result["ciphertext"], result["key"], result["iv"], result["backend"])
    assert result["backend"] == "pycryptodome"
    assert restored == b"runtime fallback vector"
    assert provider.status().backend == "pycryptodome"
    assert provider.status().asm_ready is False
    assert provider.status().reason.startswith("assembly_worker_fault")


def test_crypto_worker_environment_excludes_application_secrets(monkeypatch):
    monkeypatch.setenv("KEK_V1", "do-not-inherit")
    monkeypatch.setenv("RATE_LIMIT_PEPPER_V1", "do-not-inherit")
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    environment = CryptoProvider._worker_environment()
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "KEK_V1" not in environment
    assert "RATE_LIMIT_PEPPER_V1" not in environment
    assert "DATABASE_URL" not in environment
