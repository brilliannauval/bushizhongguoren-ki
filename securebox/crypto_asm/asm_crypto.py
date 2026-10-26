"""ctypes bindings for the supplied AES-NI, DES, and RC4 assembly routines."""

import ctypes
import ctypes.util
from pathlib import Path


SO_PATH = Path(__file__).with_name("libcrypto_asm.so")


def _load():
    if not SO_PATH.is_file():
        raise FileNotFoundError("Native assembly library is not built")
    library = ctypes.CDLL(str(SO_PATH))

    # asm_rc4_init (broken original) is intentionally NOT registered here.
    # Only asm_rc4_init_safe is wired up.
    library.asm_rc4_init_safe.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    library.asm_rc4_init_safe.restype = None

    library.asm_rc4_crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    library.asm_rc4_crypt.restype = None

    for name in ("encrypt", "decrypt"):
        fn = getattr(library, f"asm_aes128_cbc_{name}")
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
        fn.restype = None

    library.asm_des_cbc_crypt.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int
    ]
    library.asm_des_cbc_crypt.restype = None
    return library


def _zero_buffer(buf: ctypes.Array) -> None:
    """Overwrite a ctypes buffer with zeroes so key/state material does not linger.

    Fix 3: native routines do not automatically erase key schedules or cipher
    state; this helper must be called in a ``finally`` block by every caller
    that allocates such a buffer.
    """
    ctypes.memset(buf, 0, ctypes.sizeof(buf))


class AsmCrypto:
    _library = None

    @classmethod
    def _lib(cls):
        if cls._library is None:
            cls._library = _load()
        return cls._library

    @staticmethod
    def _buffer(data: bytes):
        return ctypes.create_string_buffer(data, max(1, len(data)))

    @classmethod
    def rc4_encrypt(cls, data: bytes, key: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or not key or len(key) > 256:
            raise ValueError("RC4 key must be 1–256 bytes")
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("RC4 data must be bytes")
        lib = cls._lib()
        state = ctypes.create_string_buffer(256)
        try:
            lib.asm_rc4_init_safe(state, key, len(key))
            out = ctypes.create_string_buffer(max(1, len(data)))
            lib.asm_rc4_crypt(state, data, out, len(data))
            return out.raw[: len(data)]
        finally:
            _zero_buffer(state)

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
            raise ValueError("AES-CBC requires non-empty input aligned to 16-byte blocks")
        out = ctypes.create_string_buffer(len(data))
        fn = getattr(cls._lib(), "asm_aes128_cbc_decrypt" if decrypt else "asm_aes128_cbc_encrypt")
        try:
            fn(data, out, len(data), key, iv)
            return out.raw
        finally:
            _zero_buffer(out)

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
            raise ValueError("DES-CBC requires non-empty input aligned to 8-byte blocks")
        out = ctypes.create_string_buffer(len(data))
        try:
            cls._lib().asm_des_cbc_crypt(data, out, len(data), key, iv, int(decrypt))
            return out.raw
        finally:
            _zero_buffer(out)
