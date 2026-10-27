from __future__ import annotations

import ctypes
from pathlib import Path


SO_PATH = Path(__file__).with_name("libcrypto_asm.so")


def _load():
    if not SO_PATH.is_file():
        raise FileNotFoundError("Native assembly library is not built")
    library = ctypes.CDLL(str(SO_PATH))

    library.asm_rc4_init_safe.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
    ]
    library.asm_rc4_init_safe.restype = None

    library.asm_rc4_crypt.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
    ]
    library.asm_rc4_crypt.restype = None

    for name in ("encrypt", "decrypt"):
        fn = getattr(library, f"asm_aes128_cbc_{name}")
        fn.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
        fn.restype = None

    library.asm_des_cbc_crypt.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
    ]
    library.asm_des_cbc_crypt.restype = None
    return library


def _zero_buffer(buf: "ctypes.Array[ctypes.c_char]") -> None:
    """Overwrite *buf* with zero bytes so sensitive material does not linger."""
    ctypes.memset(buf, 0, ctypes.sizeof(buf))


def _key_buf(data: bytes) -> "ctypes.Array[ctypes.c_char]":
    """Copy *data* into a mutable ctypes buffer that can be zeroed after use."""
    buf = ctypes.create_string_buffer(len(data))
    ctypes.memmove(buf, data, len(data))
    return buf


class AsmCrypto:
    _library = None

    @classmethod
    def _lib(cls):
        if cls._library is None:
            cls._library = _load()
        return cls._library

    @classmethod
    def rc4_encrypt(cls, data: bytes, key: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or not key or len(key) > 256:
            raise ValueError("RC4 key must be 1–256 bytes")
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("RC4 data must be bytes")

        lib = cls._lib()
        state = ctypes.create_string_buffer(256)
        key_buf = _key_buf(bytes(key))
        try:
            lib.asm_rc4_init_safe(state, key_buf, len(key))
            out = ctypes.create_string_buffer(max(1, len(data)))
            lib.asm_rc4_crypt(state, data, out, len(data))
            return out.raw[: len(data)]
        finally:
            _zero_buffer(state)
            _zero_buffer(key_buf)

    @classmethod
    def aes128_cbc_encrypt(cls, data: bytes, key: bytes, iv: bytes) -> bytes:
        return cls._aes_cbc(data, key, iv, decrypt=False)

    @classmethod
    def aes128_cbc_decrypt(cls, data: bytes, key: bytes, iv: bytes) -> bytes:
        return cls._aes_cbc(data, key, iv, decrypt=True)

    @classmethod
    def _aes_cbc(cls, data: bytes, key: bytes, iv: bytes, *, decrypt: bool) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 16:
            raise ValueError("AES-CBC requires a 16-byte key")
        if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
            raise ValueError("AES-CBC requires a 16-byte IV")
        if not data or len(data) % 16:
            raise ValueError("AES-CBC input must be non-empty and block-aligned (16 B)")

        key_buf = _key_buf(bytes(key))
        iv_buf = _key_buf(bytes(iv))
        out = ctypes.create_string_buffer(len(data))
        fn = getattr(cls._lib(), "asm_aes128_cbc_decrypt" if decrypt else "asm_aes128_cbc_encrypt")
        try:
            fn(data, out, len(data), key_buf, iv_buf)
            return out.raw
        finally:
            _zero_buffer(key_buf)
            _zero_buffer(iv_buf)

    @classmethod
    def des_cbc_encrypt(cls, data: bytes, key: bytes, iv: bytes) -> bytes:
        return cls._des_cbc(data, key, iv, decrypt=False)

    @classmethod
    def des_cbc_decrypt(cls, data: bytes, key: bytes, iv: bytes) -> bytes:
        return cls._des_cbc(data, key, iv, decrypt=True)

    @classmethod
    def _des_cbc(cls, data: bytes, key: bytes, iv: bytes, *, decrypt: bool) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 8:
            raise ValueError("DES-CBC requires an 8-byte key")
        if not isinstance(iv, (bytes, bytearray)) or len(iv) != 8:
            raise ValueError("DES-CBC requires an 8-byte IV")
        if not data or len(data) % 8:
            raise ValueError("DES-CBC input must be non-empty and block-aligned (8 B)")

        key_buf = _key_buf(bytes(key))
        iv_buf = _key_buf(bytes(iv))
        out = ctypes.create_string_buffer(len(data))
        try:
            cls._lib().asm_des_cbc_crypt(data, out, len(data), key_buf, iv_buf, int(decrypt))
            return out.raw
        finally:
            _zero_buffer(key_buf)
            _zero_buffer(iv_buf)
