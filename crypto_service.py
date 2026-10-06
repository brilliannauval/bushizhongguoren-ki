"""
crypto_service.py - Unified Cryptographic Engine
Supports:
  - AES-128-CBC (Block Cipher, Non-ECB mode, PKCS7 padding)
  - DES-CBC (Block Cipher, Non-ECB mode, PKCS7 padding)
  - RC4 / ARC4 (Stream Cipher)
Hardening:
  - Encrypt-then-MAC (HMAC-SHA256) with constant-time verification
  - Unique cryptographically secure random IV per block encryption
  - PBKDF2-HMAC-SHA256 Key Derivation (600,000 rounds)
  - Chunked streaming engine optimized for up to 50 MB+ files
  - Shannon Entropy and performance metrics calculators
"""

import os
import math
import time
import hmac
import hashlib
from typing import Tuple, Generator, Dict, Any, BinaryIO
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad

# Constant definitions
AES_BLOCK_SIZE = 16  # 128-bit block
DES_BLOCK_SIZE = 8   # 64-bit block
CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer (multiple of 16 and 8)
KDF_ITERATIONS = 600_000

class CryptoError(Exception):
    """Base exception for cryptographic failures."""
    pass

class AuthenticationError(CryptoError):
    """Raised when HMAC verification fails (tamper or padding oracle prevention)."""
    pass


class KeyManager:
    """Derives independent, domain-separated keys from master password and salt."""
    
    @staticmethod
    def derive_keys(passphrase: str, salt: bytes) -> Dict[str, bytes]:
        """
        Derives separate keys for AES-128 (16B), DES (8B), RC4 (16B), and HMAC (32B).
        Total key material needed: 16 + 8 + 16 + 32 = 72 bytes.
        """
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf-8')
        
        derived = hashlib.pbkdf2_hmac(
            'sha256',
            passphrase,
            salt,
            KDF_ITERATIONS,
            dklen=72
        )
        
        return {
            'aes_key': derived[0:16],       # 128-bit AES key
            'des_key': derived[16:24],      # 64-bit DES key (56 effective bits)
            'rc4_key': derived[24:40],      # 128-bit RC4 key
            'hmac_key': derived[40:72],     # 256-bit HMAC key
        }


def zeroize_buffer(buf) -> None:
    """
    Cryptographic Key & Plaintext Memory Zeroization (CWE-14 / ASVS V3.2).
    Overwrites mutable memoryview or bytearray with zeroes in-place before deallocation.
    """
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0


class CryptoVaultEngine:
    """Unified engine for encrypting and decrypting data across AES, DES, and RC4."""

    zeroize_buffer = staticmethod(zeroize_buffer)

    @staticmethod
    def compute_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (in bits per byte, max 8.0) of given data."""
        if not data:
            return 0.0
        # For large data, sample up to 256 KB to keep entropy calculation instantaneous
        sample = data[:262144] if len(data) > 262144 else data
        counts = [0] * 256
        for b in sample:
            counts[b] += 1
        entropy = 0.0
        length = len(sample)
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    # =========================================================================
    # In-Memory Encryption & Decryption (For GDPR / Database Text Fields)
    # =========================================================================

    @classmethod
    def encrypt_data(cls, plaintext: bytes, cipher_name: str, keys: Dict[str, bytes]) -> Dict[str, Any]:
        """
        Encrypts in-memory bytes with specified cipher ('aes', 'des', 'rc4').
        Returns dict containing:
          - 'ciphertext': raw bytes
          - 'iv': bytes (empty for RC4)
          - 'hmac': bytes (HMAC-SHA256 for integrity)
          - 'duration_ms': float
          - 'entropy': float
        """
        cipher_name = cipher_name.lower()
        hmac_key = keys['hmac_key']
        start_t = time.perf_counter()

        if cipher_name == 'aes':
            iv = os.urandom(AES_BLOCK_SIZE)
            padded = pad(plaintext, AES_BLOCK_SIZE)
            # Pure Assembly AES-NI first, with Python backup
            try:
                from crypto_asm.asm_crypto import AsmCrypto
                ciphertext = AsmCrypto.aes128_cbc_encrypt(padded, keys['aes_key'], iv)
            except Exception:
                cipher = AES.new(keys['aes_key'], AES.MODE_CBC, iv=iv)
                ciphertext = cipher.encrypt(padded)
            # Encrypt-then-MAC: HMAC over IV + Ciphertext
            mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

        elif cipher_name == 'des':
            iv = os.urandom(DES_BLOCK_SIZE)
            padded = pad(plaintext, DES_BLOCK_SIZE)
            # Pure Assembly first, with Python backup
            try:
                from crypto_asm.asm_crypto import AsmCrypto
                ciphertext = AsmCrypto.des_cbc_encrypt(padded, keys['des_key'], iv)
            except Exception:
                cipher = DES.new(keys['des_key'], DES.MODE_CBC, iv=iv)
                ciphertext = cipher.encrypt(padded)
            mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

        elif cipher_name == 'rc4':
            iv = b""  # RC4 is a stream cipher, no IV
            # Pure Assembly first, with Python backup
            try:
                from crypto_asm.asm_crypto import AsmCrypto
                ciphertext = AsmCrypto.rc4_encrypt(plaintext, keys['rc4_key'])
            except Exception:
                cipher = ARC4.new(keys['rc4_key'])
                ciphertext = cipher.encrypt(plaintext)
            mac = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()

        else:
            raise ValueError(f"Unsupported cipher: {cipher_name}. Choose 'aes', 'des', or 'rc4'.")

        duration_ms = (time.perf_counter() - start_t) * 1000.0
        entropy = cls.compute_entropy(ciphertext)

        return {
            'ciphertext': ciphertext,
            'iv': iv,
            'hmac': mac,
            'duration_ms': round(duration_ms, 4),
            'entropy': entropy,
            'size_bytes': len(ciphertext)
        }

    @classmethod
    def decrypt_data(cls, ciphertext: bytes, cipher_name: str, iv: bytes,
                     mac: bytes, keys: Dict[str, bytes]) -> Tuple[bytes, float]:
        """
        Decrypts in-memory bytes with specified cipher.
        Verifies HMAC in constant-time prior to padding check to prevent Padding Oracle.
        Returns (plaintext_bytes, duration_ms).
        """
        cipher_name = cipher_name.lower()
        hmac_key = keys['hmac_key']
        start_t = time.perf_counter()

        # 1. Constant-Time Integrity / Authenticity check
        if cipher_name in ('aes', 'des'):
            expected_mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
        elif cipher_name == 'rc4':
            expected_mac = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
        else:
            raise ValueError(f"Unsupported cipher: {cipher_name}")

        if not hmac.compare_digest(mac, expected_mac):
            raise AuthenticationError("Tampering detected! HMAC verification failed.")

        # 2. Decrypt
        try:
            if cipher_name == 'aes':
                # Pure Assembly AES-NI first, with Python backup
                try:
                    from crypto_asm.asm_crypto import AsmCrypto
                    padded = AsmCrypto.aes128_cbc_decrypt(ciphertext, keys['aes_key'], iv)
                except Exception:
                    cipher = AES.new(keys['aes_key'], AES.MODE_CBC, iv=iv)
                    padded = cipher.decrypt(ciphertext)
                plaintext = unpad(padded, AES_BLOCK_SIZE)
            elif cipher_name == 'des':
                # Pure Assembly first, with Python backup
                try:
                    from crypto_asm.asm_crypto import AsmCrypto
                    padded = AsmCrypto.des_cbc_decrypt(ciphertext, keys['des_key'], iv)
                except Exception:
                    cipher = DES.new(keys['des_key'], DES.MODE_CBC, iv=iv)
                    padded = cipher.decrypt(ciphertext)
                plaintext = unpad(padded, DES_BLOCK_SIZE)

            elif cipher_name == 'rc4':
                # Pure Assembly first, with Python backup
                try:
                    from crypto_asm.asm_crypto import AsmCrypto
                    plaintext = AsmCrypto.rc4_encrypt(ciphertext, keys['rc4_key'])
                except Exception:
                    cipher = ARC4.new(keys['rc4_key'])
                    plaintext = cipher.decrypt(ciphertext)
        except (ValueError, KeyError) as e:
            raise CryptoError(f"Decryption failed: {str(e)}")

        duration_ms = (time.perf_counter() - start_t) * 1000.0
        return plaintext, round(duration_ms, 4)

    # =========================================================================
    # Streaming File Encryption & Decryption (For 50 MB+ Videos, Docs, Images)
    # File Storage Format:
    #   [16-byte magic "VAULT_ENC_v1\x00\x00\x00\x00"]
    #   [4-byte cipher identifier ("AES\x00", "DES\x00", "RC4\x00")]
    #   [16-byte IV field (AES: 16B, DES: 8B + 8B zeros, RC4: 16B zeros)]
    #   [32-byte HMAC-SHA256 signature]
    #   [Remaining bytes: Encrypted Payload]
    # =========================================================================

    MAGIC_HEADER = b"VAULT_ENC_v1\x00\x00\x00\x00"

    @classmethod
    def encrypt_file_stream(cls, in_stream: BinaryIO, out_path: str,
                            cipher_name: str, keys: Dict[str, bytes]) -> Dict[str, Any]:
        """
        Encrypts an arbitrary stream (e.g. up to 50 MB file) to disk using buffered chunks.
        Computes HMAC on the fly using Encrypt-then-MAC.
        """
        cipher_name = cipher_name.lower()
        hmac_key = keys['hmac_key']
        mac_ctx = hmac.new(hmac_key, b"", hashlib.sha256)
        start_t = time.perf_counter()

        if cipher_name == 'aes':
            iv = os.urandom(AES_BLOCK_SIZE)
            cipher = AES.new(keys['aes_key'], AES.MODE_CBC, iv=iv)
            block_size = AES_BLOCK_SIZE
            cipher_tag = b"AES\x00"
            iv_field = iv
        elif cipher_name == 'des':
            iv = os.urandom(DES_BLOCK_SIZE)
            cipher = DES.new(keys['des_key'], DES.MODE_CBC, iv=iv)
            block_size = DES_BLOCK_SIZE
            cipher_tag = b"DES\x00"
            iv_field = iv + (b"\x00" * 8)  # Pad to 16 bytes
        elif cipher_name == 'rc4':
            iv = b""
            cipher = ARC4.new(keys['rc4_key'])
            block_size = 0
            cipher_tag = b"RC4\x00"
            iv_field = b"\x00" * 16
        else:
            raise ValueError(f"Unsupported cipher: {cipher_name}")

        # Incorporate IV into MAC for CBC ciphers
        if iv:
            mac_ctx.update(iv)

        # Temporary file to store ciphertext while computing HMAC
        tmp_path = out_path + ".tmp"
        total_ciphertext_bytes = 0
        first_chunk_entropy_sample = b""

        # Read stream with lookahead to handle last block padding cleanly
        current_chunk = in_stream.read(CHUNK_SIZE)
        
        try:
            with open(tmp_path, "wb") as f_out:
                while current_chunk:
                    next_chunk = in_stream.read(CHUNK_SIZE)
                    is_last = (len(next_chunk) == 0)
                    
                    if is_last:
                        if block_size > 0:
                            padded_chunk = pad(current_chunk, block_size)
                            enc = cipher.encrypt(padded_chunk)
                        else:
                            enc = cipher.encrypt(current_chunk)
                    else:
                        enc = cipher.encrypt(current_chunk)
                    
                    f_out.write(enc)
                    mac_ctx.update(enc)
                    total_ciphertext_bytes += len(enc)
                    
                    if not first_chunk_entropy_sample:
                        first_chunk_entropy_sample = enc[:4096]
                        
                    current_chunk = next_chunk

                # If input was completely empty:
                if total_ciphertext_bytes == 0 and block_size > 0:
                    padded_tail = pad(b"", block_size)
                    enc_tail = cipher.encrypt(padded_tail)
                    f_out.write(enc_tail)
                    mac_ctx.update(enc_tail)
                    total_ciphertext_bytes += len(enc_tail)

            final_mac = mac_ctx.digest()

            # Write final file with full header + payload
            with open(out_path, "wb") as f_final:
                f_final.write(cls.MAGIC_HEADER)   # 16 bytes
                f_final.write(cipher_tag)          # 4 bytes
                f_final.write(iv_field)            # 16 bytes
                f_final.write(final_mac)           # 32 bytes
                
                # Stream payload from tmp_path
                with open(tmp_path, "rb") as f_tmp:
                    while True:
                        buf = f_tmp.read(CHUNK_SIZE)
                        if not buf:
                            break
                        f_final.write(buf)

        except Exception:
            # On stream abort or write error, clean up out_path immediately
            if os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except OSError:
                    pass
            raise
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        duration_ms = (time.perf_counter() - start_t) * 1000.0
        entropy = cls.compute_entropy(first_chunk_entropy_sample)
        total_file_size = os.path.getsize(out_path)

        return {
            'duration_ms': round(duration_ms, 2),
            'ciphertext_size': total_ciphertext_bytes,
            'total_stored_size': total_file_size,
            'entropy': entropy,
            'cipher': cipher_name
        }

    @classmethod
    def decrypt_file_stream(cls, in_path: str, cipher_name: str,
                            keys: Dict[str, bytes]) -> Generator[bytes, None, None]:
        """
        Streams decrypted bytes generator from an encrypted vault file.
        Verifies header and HMAC in constant time.
        """
        cipher_name = cipher_name.lower()
        hmac_key = keys['hmac_key']

        if not os.path.exists(in_path):
            raise FileNotFoundError(f"Encrypted vault file not found: {in_path}")

        file_size = os.path.getsize(in_path)
        header_len = 16 + 4 + 16 + 32  # 68 bytes
        if file_size < header_len:
            raise CryptoError("Corrupted vault file: header is truncated.")

        with open(in_path, "rb") as f:
            magic = f.read(16)
            cipher_tag = f.read(4)
            iv_field = f.read(16)
            stored_mac = f.read(32)

            if magic != cls.MAGIC_HEADER:
                raise CryptoError("Invalid vault file magic signature.")

            tag_str = cipher_tag.decode('ascii', errors='ignore').strip('\x00').lower()
            if tag_str != cipher_name:
                raise CryptoError(f"Cipher mismatch: file encrypted with {tag_str}, requested {cipher_name}.")

            if cipher_name == 'aes':
                iv = iv_field
                cipher = AES.new(keys['aes_key'], AES.MODE_CBC, iv=iv)
                block_size = AES_BLOCK_SIZE
            elif cipher_name == 'des':
                iv = iv_field[:8]
                cipher = DES.new(keys['des_key'], DES.MODE_CBC, iv=iv)
                block_size = DES_BLOCK_SIZE
            elif cipher_name == 'rc4':
                iv = b""
                cipher = ARC4.new(keys['rc4_key'])
                block_size = 0
            else:
                raise ValueError(f"Unsupported cipher: {cipher_name}")

            # 1. First pass: Verify HMAC to eliminate Padding Oracle
            mac_ctx = hmac.new(hmac_key, b"", hashlib.sha256)
            if iv:
                mac_ctx.update(iv)
            
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                mac_ctx.update(chunk)

            calculated_mac = mac_ctx.digest()
            if not hmac.compare_digest(stored_mac, calculated_mac):
                raise AuthenticationError("Tampering detected in encrypted file! HMAC validation failed.")

            # 2. Second pass: Decrypt & stream yield
            f.seek(header_len)
            prev_decrypted = b""
            
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    # Finalize unpadding for block ciphers
                    if block_size > 0 and prev_decrypted:
                        try:
                            unpadded = unpad(prev_decrypted, block_size)
                            yield unpadded
                        except ValueError as e:
                            raise CryptoError("Padding corruption during decryption.") from e
                    elif prev_decrypted:
                        yield prev_decrypted
                    break

                if block_size > 0:
                    dec = cipher.decrypt(chunk)
                    if prev_decrypted:
                        yield prev_decrypted
                    prev_decrypted = dec
                else:
                    yield cipher.decrypt(chunk)
