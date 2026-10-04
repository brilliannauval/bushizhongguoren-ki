"""
asm_crypto.py - Python ctypes wrapper for libcrypto_asm.so
Provides:
  - RC4 (x86_64 Assembly): asm_rc4_crypt
  - AES-NI (x86_64 Hardware Instructions): asm_aes128_encrypt_block, asm_aes128_decrypt_block
  - DES (Native 64-bit Feistel): asm_des_cbc_crypt, asm_des_encrypt_block, asm_des_decrypt_block
"""

import os
import ctypes
from typing import Tuple

SO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libcrypto_asm.so")

if not os.path.exists(SO_PATH):
    raise FileNotFoundError(f"Shared library {SO_PATH} not found. Run 'make -C crypto_asm' first.")

_lib = ctypes.CDLL(SO_PATH)

# =============================================================================
# 1. RC4 Assembly Signatures
# =============================================================================
_lib.asm_rc4_init_safe.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int
]
_lib.asm_rc4_init_safe.restype = None

_lib.asm_rc4_crypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t
]
_lib.asm_rc4_crypt.restype = None

# =============================================================================
# 2. AES-NI Assembly Signatures
# =============================================================================
_lib.asm_aes128_encrypt_block.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p
]
_lib.asm_aes128_encrypt_block.restype = None

_lib.asm_aes128_decrypt_block.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p
]
_lib.asm_aes128_decrypt_block.restype = None

_lib.asm_aes128_cbc_encrypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p
]
_lib.asm_aes128_cbc_encrypt.restype = None

_lib.asm_aes128_cbc_decrypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p
]
_lib.asm_aes128_cbc_decrypt.restype = None

# =============================================================================
# 3. DES Native Signatures
# =============================================================================
# void asm_des_cbc_crypt(const uint8_t *in, uint8_t *out, size_t len,
#                        const uint8_t key[8], const uint8_t iv[8], int decrypt)
_lib.asm_des_cbc_crypt.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int
]
_lib.asm_des_cbc_crypt.restype = None


class AsmCrypto:
    @staticmethod
    def rc4_encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypts or decrypts data using pure x86_64 assembly RC4."""
        state = ctypes.create_string_buffer(256)
        _lib.asm_rc4_init_safe(state, key, len(key))
        
        out_buf = ctypes.create_string_buffer(len(data))
        _lib.asm_rc4_crypt(state, data, out_buf, len(data))
        return out_buf.raw

    @staticmethod
    def aes128_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypts a buffer (length multiple of 16) using pure assembly AES-NI in CBC mode."""
        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes (128 bits).")
        if len(iv) != 16:
            raise ValueError("AES-128 IV must be exactly 16 bytes.")
        if len(data) % 16 != 0:
            raise ValueError("Data length must be a multiple of 16 for AES block encryption.")

        out_buf = ctypes.create_string_buffer(len(data))
        _lib.asm_aes128_cbc_encrypt(data, out_buf, len(data), key, iv)
        return out_buf.raw

    @staticmethod
    def aes128_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypts a buffer (length multiple of 16) using pure assembly AES-NI in CBC mode."""
        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes (128 bits).")
        if len(iv) != 16:
            raise ValueError("AES-128 IV must be exactly 16 bytes.")
        if len(data) % 16 != 0:
            raise ValueError("Data length must be a multiple of 16 for AES block decryption.")

        out_buf = ctypes.create_string_buffer(len(data))
        _lib.asm_aes128_cbc_decrypt(data, out_buf, len(data), key, iv)
        return out_buf.raw

    @staticmethod
    def des_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypts a buffer (length multiple of 8) using native DES-CBC."""
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes (56 bits + 8 parity bits).")
        if len(iv) != 8:
            raise ValueError("DES IV must be exactly 8 bytes.")
        if len(data) % 8 != 0:
            raise ValueError("Data length must be a multiple of 8 for DES block encryption.")

        out_buf = ctypes.create_string_buffer(len(data))
        _lib.asm_des_cbc_crypt(data, out_buf, len(data), key, iv, 0)
        return out_buf.raw

    @staticmethod
    def des_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypts a buffer (length multiple of 8) using native DES-CBC."""
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes.")
        if len(iv) != 8:
            raise ValueError("DES IV must be exactly 8 bytes.")
        if len(data) % 8 != 0:
            raise ValueError("Data length must be a multiple of 8 for DES block decryption.")

        out_buf = ctypes.create_string_buffer(len(data))
        _lib.asm_des_cbc_crypt(data, out_buf, len(data), key, iv, 1)
        return out_buf.raw

    @staticmethod
    def is_available() -> bool:
        return os.path.exists(SO_PATH)
