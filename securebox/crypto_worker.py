"""Single-operation child process for native crypto and bounded fallback work."""

from __future__ import annotations

import json
import os
import struct
import sys
import time

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad, unpad


def _host_supports_aesni() -> bool:
    if sys.platform != "linux" or os.uname().machine not in {"x86_64", "amd64"}:
        return False
    try:
        with open("/proc/cpuinfo", "r", encoding="ascii") as cpuinfo:
            flags = set()
            for line in cpuinfo:
                if line.lower().startswith("flags"):
                    flags.update(line.split(":", 1)[1].split())
                    break
        return {"aes", "sse4_1"}.issubset(flags)
    except OSError:
        return False


def _asm():
    if not _host_supports_aesni():
        raise RuntimeError("assembly requires Linux x86-64 with AES-NI and SSE4.1")
    from .crypto_asm.asm_crypto import AsmCrypto

    return AsmCrypto


def _self_test() -> dict:
    asm = _asm()
    aes_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    aes_iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    aes_plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    aes_expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    aes_out = asm.aes128_cbc_encrypt(aes_plain, aes_key, aes_iv)
    if aes_out != aes_expected or asm.aes128_cbc_decrypt(aes_out, aes_key, aes_iv) != aes_plain:
        raise RuntimeError("AES assembly known-answer test failed")

    des_key = bytes.fromhex("133457799bbcdff1")
    des_iv = bytes(8)
    des_plain = bytes.fromhex("0123456789abcdef")
    des_expected = bytes.fromhex("85e813540f0ab405")
    des_out = asm.des_cbc_encrypt(des_plain, des_key, des_iv)
    if des_out != des_expected or asm.des_cbc_decrypt(des_out, des_key, des_iv) != des_plain:
        raise RuntimeError("DES assembly known-answer test failed")

    rc4_key, rc4_plain = b"Key", b"Plaintext"
    rc4_expected = bytes.fromhex("bbf316e8d940af0ad3")
    rc4_out = asm.rc4_encrypt(rc4_plain, rc4_key)
    if rc4_out != rc4_expected or asm.rc4_encrypt(rc4_out, rc4_key) != rc4_plain:
        raise RuntimeError("RC4 assembly known-answer test failed")

    # Differential checks use independent PyCryptodome implementations.
    if AES.new(aes_key, AES.MODE_CBC, iv=aes_iv).encrypt(aes_plain) != aes_out:
        raise RuntimeError("AES differential test failed")
    if DES.new(des_key, DES.MODE_CBC, iv=des_iv).encrypt(des_plain) != des_out:
        raise RuntimeError("DES differential test failed")
    if ARC4.new(rc4_key).encrypt(rc4_plain) != rc4_out:
        raise RuntimeError("RC4 differential test failed")
    return {"ok": True, "algorithms": ["aes", "des", "rc4"]}


def _transform(header: dict, payload: bytes) -> tuple[dict, bytes]:
    algorithm = header["algorithm"]
    operation = header["operation"]
    backend = header["backend"]
    key = bytes.fromhex(header["key"])
    iv = bytes.fromhex(header.get("iv", ""))
    started = time.perf_counter_ns()
    if backend == "asm":
        asm = _asm()
        if algorithm == "aes":
            block_data = pad(payload, AES.block_size) if operation == "encrypt" else payload
            output = asm.aes128_cbc_encrypt(block_data, key, iv) if operation == "encrypt" else asm.aes128_cbc_decrypt(block_data, key, iv)
            if operation == "decrypt":
                output = unpad(output, AES.block_size)
        elif algorithm == "des":
            block_data = pad(payload, DES.block_size) if operation == "encrypt" else payload
            output = asm.des_cbc_encrypt(block_data, key, iv) if operation == "encrypt" else asm.des_cbc_decrypt(block_data, key, iv)
            if operation == "decrypt":
                output = unpad(output, DES.block_size)
        elif algorithm == "rc4":
            output = asm.rc4_encrypt(payload, key)
        else:
            raise ValueError("Unsupported algorithm")
    elif backend == "python":
        if algorithm == "aes":
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            output = cipher.encrypt(pad(payload, AES.block_size)) if operation == "encrypt" else unpad(cipher.decrypt(payload), AES.block_size)
        elif algorithm == "des":
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
            output = cipher.encrypt(pad(payload, DES.block_size)) if operation == "encrypt" else unpad(cipher.decrypt(payload), DES.block_size)
        elif algorithm == "rc4":
            output = ARC4.new(key).encrypt(payload)
        else:
            raise ValueError("Unsupported algorithm")
    else:
        raise ValueError("Unsupported backend")
    elapsed_ns = time.perf_counter_ns() - started
    return {"backend": "x86_64-assembly" if backend == "asm" else "pycryptodome", "elapsed_ns": elapsed_ns}, output


def _read_frame() -> tuple[dict, bytes]:
    header_len_raw = sys.stdin.buffer.read(4)
    if len(header_len_raw) != 4:
        raise ValueError("Missing operation header")
    header_len = struct.unpack(">I", header_len_raw)[0]
    if not 1 <= header_len <= 4096:
        raise ValueError("Invalid operation header")
    header = json.loads(sys.stdin.buffer.read(header_len))
    payload = sys.stdin.buffer.read()
    return header, payload


def main() -> int:
    if sys.argv[1:] == ["--kat"]:
        try:
            result = _self_test()
            sys.stdout.write(json.dumps(result, separators=(",", ":")))
            return 0
        except Exception:
            sys.stdout.write(json.dumps({"ok": False, "reason": "known_answer_test_failed"}, separators=(",", ":")))
            return 1
    try:
        header, payload = _read_frame()
        result, output = _transform(header, payload)
        header_bytes = json.dumps(result, separators=(",", ":")).encode("ascii")
        sys.stdout.buffer.write(struct.pack(">I", len(header_bytes)) + header_bytes + output)
        return 0
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
