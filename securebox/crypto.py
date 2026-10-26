from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import platform
import secrets
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from Crypto.Cipher import DES

from .envelope import pack_inner_material, unpack_inner_material

logger = logging.getLogger(__name__)


class CryptoError(RuntimeError):
    pass


class NativeCryptoFault(CryptoError):
    pass


_WEAK_DES_KEYS = {
    bytes.fromhex(value)
    for value in (
        "0101010101010101", "fefefefefefefefe", "e0e0e0e0f1f1f1f1", "1f1f1f1f0e0e0e0e",
        "01fe01fe01fe01fe", "fe01fe01fe01fe01", "1fe01fe00ef10ef1", "e01fe01ff10ef10e",
        "01e001e001f101f1", "e001e001f101f101", "1ffe1ffe0efe0efe", "fe1ffe1ffe0efe0e",
        "011f011f010e010e", "1f011f010e010e01", "e0fee0fef1fef1fe", "fee0fee0fef1fef1",
    )
}


def _odd_parity(key: bytes) -> bytes:
    normalized = bytearray()
    for value in key:
        upper = value & 0xFE
        normalized.append(upper | (1 ^ (upper.bit_count() & 1)))
    return bytes(normalized)


@dataclass(frozen=True)
class CryptoStatus:
    backend: str
    asm_ready: bool
    reason: str


class CryptoProvider:
    """Native assembly is preflighted in a child; native calls never run in the API process."""

    def __init__(self, timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._status: CryptoStatus | None = None

    @staticmethod
    def _worker_environment() -> dict[str, str]:
        """Pass only execution essentials; crypto workers never need app secrets."""
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        # Windows Python needs this for system DLL discovery when using the fallback.
        for name in ("SYSTEMROOT", "WINDIR"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        return environment

    @staticmethod
    def _cpu_supports_asm() -> tuple[bool, str]:
        if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
            return False, "requires_linux_x86_64"
        try:
            flags = set()
            for line in Path("/proc/cpuinfo").read_text(encoding="ascii").splitlines():
                if line.lower().startswith("flags"):
                    flags.update(line.split(":", 1)[1].split())
                    break
            if not {"aes", "sse4_1"}.issubset(flags):
                return False, "missing_aes_ni_or_sse4_1"
        except OSError:
            return False, "cpu_flags_unavailable"
        lib = Path(__file__).with_name("crypto_asm") / "libcrypto_asm.so"
        if not lib.is_file():
            return False, "assembly_library_missing"
        return True, ""

    def status(self) -> CryptoStatus:
        if self._status is None:
            with self._lock:
                if self._status is None:
                    supported, reason = self._cpu_supports_asm()
                    if not supported:
                        self._status = CryptoStatus("pycryptodome", False, reason)
                    else:
                        try:
                            result = subprocess.run(
                                [sys.executable, "-m", "securebox.crypto_worker", "--kat"],
                                cwd=Path(__file__).resolve().parents[1],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                timeout=5,
                                check=False,
                                env=self._worker_environment(),
                                preexec_fn=_limits if os.name == "posix" else None,
                            )
                            detail = json.loads(result.stdout or b"{}")
                            if result.returncode == 0 and detail.get("ok") is True:
                                self._status = CryptoStatus("x86_64-assembly", True, "known_answer_tests_passed")
                            elif result.returncode < 0:
                                self._status = CryptoStatus("pycryptodome", False, "assembly_self_test_process_fault")
                            else:
                                self._status = CryptoStatus("pycryptodome", False, "assembly_self_test_failed")
                        except subprocess.TimeoutExpired:
                            self._status = CryptoStatus("pycryptodome", False, "assembly_self_test_timeout")
                        except Exception:
                            self._status = CryptoStatus("pycryptodome", False, "assembly_self_test_unavailable")
        return self._status

    def _quarantine(self, reason: str) -> None:
        with self._lock:
            self._status = CryptoStatus("pycryptodome", False, f"{reason}_python_fallback")
        logger.warning("native_backend_quarantined reason=%s", reason)

    def _run(self, algorithm: str, operation: str, data: bytes, key: bytes, iv: bytes, backend: str | None = None) -> tuple[bytes, int, str]:
        status = self.status()
        selected = backend or status.backend
        if selected == "unavailable":
            raise CryptoError("No approved crypto backend is available")
        if selected not in {"x86_64-assembly", "pycryptodome"}:
            raise CryptoError("Unknown crypto backend")
        if selected == "x86_64-assembly" and not status.asm_ready:
            raise NativeCryptoFault("Native backend is quarantined")
        header = json.dumps(
            {"algorithm": algorithm, "operation": operation, "backend": "asm" if selected == "x86_64-assembly" else "python", "key": key.hex(), "iv": iv.hex()},
            separators=(",", ":"),
        ).encode("ascii")
        framed = struct.pack(">I", len(header)) + header + data
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "securebox.crypto_worker"],
                cwd=Path(__file__).resolve().parents[1],
                input=framed,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout_seconds,
                check=False,
                env=self._worker_environment(),
                preexec_fn=_limits if os.name == "posix" else None,
            )
        except subprocess.TimeoutExpired as exc:
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_timeout")
                raise NativeCryptoFault("Native crypto worker exceeded its time limit") from exc
            raise CryptoError("Crypto worker exceeded its time limit") from exc
        if completed.returncode != 0:
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_fault")
                raise NativeCryptoFault("Native crypto worker failed")
            raise CryptoError("Crypto worker failed")
        if len(completed.stdout) < 4:
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_invalid_response")
                raise NativeCryptoFault("Native crypto worker returned an invalid response")
            raise CryptoError("Crypto worker returned an invalid result")
        header_size = struct.unpack(">I", completed.stdout[:4])[0]
        if not 1 <= header_size <= 2048 or 4 + header_size > len(completed.stdout):
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_invalid_response")
                raise NativeCryptoFault("Native crypto worker returned an invalid response")
            raise CryptoError("Crypto worker returned an invalid result")
        try:
            result = json.loads(completed.stdout[4 : 4 + header_size])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_invalid_response")
                raise NativeCryptoFault("Native crypto worker returned an invalid response") from exc
            raise CryptoError("Crypto worker returned an invalid result") from exc
        if not isinstance(result, dict) or not isinstance(result.get("elapsed_ns"), int):
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_invalid_response")
                raise NativeCryptoFault("Native crypto worker returned an invalid response")
            raise CryptoError("Crypto worker returned an invalid result")
        output = completed.stdout[4 + header_size :]
        if result.get("backend") != selected:
            if selected == "x86_64-assembly":
                self._quarantine("assembly_worker_backend_mismatch")
                raise NativeCryptoFault("Native crypto worker backend mismatch")
            raise CryptoError("Crypto worker backend mismatch")
        return output, int(result["elapsed_ns"]), selected

    def _encrypt_once(self, algorithm: str, plaintext: bytes, backend: str | None) -> tuple[bytes, bytes, bytes, int, str]:
        if algorithm == "aes":
            key, iv = secrets.token_bytes(16), secrets.token_bytes(16)
            expected_size = ((len(plaintext) // 16) + 1) * 16
        elif algorithm == "des":
            while True:
                key = _odd_parity(secrets.token_bytes(8))
                if key not in _WEAK_DES_KEYS:
                    break
            iv = secrets.token_bytes(8)
            expected_size = ((len(plaintext) // 8) + 1) * 8
        elif algorithm == "rc4":
            key, iv = secrets.token_bytes(16), b""
            expected_size = len(plaintext)
        else:
            raise ValueError("Unsupported algorithm")
        ciphertext, elapsed, selected = self._run(algorithm, "encrypt", plaintext, key, iv, backend)
        if len(ciphertext) != expected_size:
            if selected == "x86_64-assembly":
                self._quarantine("assembly_output_size_mismatch")
                raise NativeCryptoFault("Native crypto worker returned an invalid output length")
            raise CryptoError("Crypto worker returned an invalid output length")
        return ciphertext, key, iv, elapsed, selected

    def encrypt(self, algorithm: str, plaintext: bytes, backend: str | None = None) -> tuple[bytes, bytes, bytes, int, str]:
        selected = backend or self.status().backend
        try:
            return self._encrypt_once(algorithm, plaintext, selected)
        except NativeCryptoFault:
            if selected != "x86_64-assembly":
                raise
            logger.warning("native_operation_fallback algorithm=%s operation=encrypt backend=pycryptodome", algorithm)
            return self._encrypt_once(algorithm, plaintext, "pycryptodome")

    def decrypt_labeled(self, algorithm: str, ciphertext: bytes, key: bytes, iv: bytes, backend: str) -> tuple[bytes, int, str]:
        try:
            return self._run(algorithm, "decrypt", ciphertext, key, iv, backend)
        except NativeCryptoFault:
            if backend != "x86_64-assembly":
                raise
            logger.warning("native_operation_fallback algorithm=%s operation=decrypt backend=pycryptodome", algorithm)
            return self._run(algorithm, "decrypt", ciphertext, key, iv, "pycryptodome")

    def decrypt(self, algorithm: str, ciphertext: bytes, key: bytes, iv: bytes, backend: str) -> tuple[bytes, int]:
        output, elapsed, _actual_backend = self.decrypt_labeled(algorithm, ciphertext, key, iv, backend)
        return output, elapsed

    def _make_variant_once(self, algorithm: str, plaintext: bytes, backend: str) -> dict:
        ciphertext, key, iv, elapsed, actual_backend = self._encrypt_once(algorithm, plaintext, backend)
        clear, decrypt_ns, decrypt_backend = self._run(algorithm, "decrypt", ciphertext, key, iv, actual_backend)
        if clear != plaintext:
            if actual_backend == "x86_64-assembly":
                self._quarantine("assembly_round_trip_mismatch")
                raise NativeCryptoFault("Native crypto self-verification failed")
            raise CryptoError("Crypto self-verification failed")
        if decrypt_backend != actual_backend:
            raise CryptoError("Crypto round-trip used different backends")
        return {
            "ciphertext": ciphertext,
            "key": key,
            "iv": iv,
            "backend": actual_backend,
            "encrypt_ns": elapsed,
            "decrypt_ns": decrypt_ns,
        }

    def make_variant(self, algorithm: str, plaintext: bytes) -> dict:
        selected = self.status().backend
        try:
            return self._make_variant_once(algorithm, plaintext, selected)
        except NativeCryptoFault:
            if selected != "x86_64-assembly":
                raise
            logger.warning("native_operation_fallback algorithm=%s operation=variant backend=pycryptodome", algorithm)
            return self._make_variant_once(algorithm, plaintext, "pycryptodome")

    def _benchmark_once(self, algorithm: str, data: bytes, samples: int, backend: str) -> dict:
        seed = self._make_variant_once(algorithm, data, backend)
        actual_backend = seed["backend"]
        if actual_backend != backend:
            raise CryptoError("Benchmark seed backend mismatch")
        # Warm up once, then measure only the inner cipher calls in child processes.
        self._run(algorithm, "encrypt", data, seed["key"], seed["iv"], actual_backend)
        encrypt_ns, decrypt_ns = [], []
        ciphertext = seed["ciphertext"]
        for _ in range(samples):
            measured, elapsed, _ = self._run(algorithm, "encrypt", data, seed["key"], seed["iv"], actual_backend)
            if measured != ciphertext:
                if actual_backend == "x86_64-assembly":
                    self._quarantine("assembly_benchmark_encrypt_mismatch")
                    raise NativeCryptoFault("Native benchmark encryption verification failed")
                raise CryptoError("Benchmark encryption verification failed")
            encrypt_ns.append(elapsed)
            restored, elapsed, _ = self._run(algorithm, "decrypt", ciphertext, seed["key"], seed["iv"], actual_backend)
            if restored != data:
                if actual_backend == "x86_64-assembly":
                    self._quarantine("assembly_benchmark_round_trip_mismatch")
                    raise NativeCryptoFault("Native benchmark round-trip verification failed")
                raise CryptoError("Benchmark round-trip verification failed")
            decrypt_ns.append(elapsed)
        return {
            "backend": actual_backend,
            "mode": {"aes": "AES-128-CBC/PKCS7", "des": "DES-CBC/PKCS7", "rc4": "RC4"}[algorithm],
            "input_bytes": len(data),
            "sample_count": samples,
            "warmups": 1,
            "encrypt_ns": _summary(encrypt_ns, len(data)),
            "decrypt_ns": _summary(decrypt_ns, len(data)),
        }

    def benchmark(self, algorithm: str, data: bytes, samples: int = 5) -> dict:
        if not 5 <= samples <= 10:
            raise ValueError("Benchmark sample count must be from 5 through 10")
        selected = self.status().backend
        try:
            return self._benchmark_once(algorithm, data, samples, selected)
        except NativeCryptoFault:
            if selected != "x86_64-assembly":
                raise
            logger.warning("native_operation_fallback algorithm=%s operation=benchmark backend=pycryptodome", algorithm)
            return self._benchmark_once(algorithm, data, samples, "pycryptodome")


def _summary(values: list[int], byte_count: int) -> dict:
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, max(0, int(0.95 * len(ordered) + 0.999) - 1))]
    median = int(statistics.median(ordered))
    return {
        "min_ns": ordered[0],
        "median_ns": median,
        "p95_ns": p95,
        "max_ns": ordered[-1],
        "throughput_mib_s_at_median": round(byte_count / max(median, 1) * 1_000_000_000 / (1024 * 1024), 3),
        "samples_ns": ordered,
    }


def _limits() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        max_memory = 256 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (max_memory, max_memory))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        os.umask(0o077)
    except (ImportError, OSError, ValueError):
        pass
