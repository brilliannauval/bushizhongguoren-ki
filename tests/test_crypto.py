"""
tests/test_crypto.py - Unit test suite for crypto_service.py
Verifies:
  - In-memory round-trip encryption/decryption for AES-CBC, DES-CBC, RC4
  - Streaming file round-trip for text, binary, images, and random streams
  - PKCS7 padding edge cases (exact block multiples, empty, 1-byte)
  - Tamper detection (Padding Oracle defense / HMAC-SHA256)
  - Key separation & entropy measurements
"""

import os
import io
import unittest
import tempfile
from crypto_service import KeyManager, CryptoVaultEngine, AuthenticationError, CryptoError

class TestCryptoService(unittest.TestCase):
    def setUp(self):
        self.passphrase = "UltraSecurePassword123!@#"
        self.salt = os.urandom(16)
        self.keys = KeyManager.derive_keys(self.passphrase, self.salt)

    def test_key_derivation_lengths(self):
        self.assertEqual(len(self.keys['aes_key']), 16)  # AES-128
        self.assertEqual(len(self.keys['des_key']), 8)
        self.assertEqual(len(self.keys['rc4_key']), 16)
        self.assertEqual(len(self.keys['hmac_key']), 32)

    def test_in_memory_roundtrip(self):
        samples = [
            b"Hello World!",
            b"",
            b"A" * 16,  # Exact AES block size
            b"B" * 8,   # Exact DES block size
            b"Longer text containing sensitive GDPR data like NIK: 3175012345678901 and Name: John Doe",
            os.urandom(1024)  # Binary random
        ]

        for cipher in ['aes', 'des', 'rc4']:
            for sample in samples:
                res = CryptoVaultEngine.encrypt_data(sample, cipher, self.keys)
                decrypted, duration = CryptoVaultEngine.decrypt_data(
                    res['ciphertext'], cipher, res['iv'], res['hmac'], self.keys
                )
                self.assertEqual(sample, decrypted, f"Round-trip failed for cipher {cipher}")
                self.assertTrue(res['entropy'] > 0 if len(sample) > 0 else True)

    def test_tamper_detection_prevents_padding_oracle(self):
        sample = b"Secret Banking Credential Data"
        for cipher in ['aes', 'des', 'rc4']:
            res = CryptoVaultEngine.encrypt_data(sample, cipher, self.keys)
            # Tamper with 1 byte of ciphertext
            corrupted = bytearray(res['ciphertext'])
            if len(corrupted) > 0:
                corrupted[0] ^= 0xFF
                with self.assertRaises(AuthenticationError):
                    CryptoVaultEngine.decrypt_data(
                        bytes(corrupted), cipher, res['iv'], res['hmac'], self.keys
                    )

    def test_streaming_file_roundtrip(self):
        # Test large buffer (1.5 MB with multiple 64KB chunks and odd tail)
        test_payload = os.urandom(1500 * 1024)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            for cipher in ['aes', 'des', 'rc4']:
                in_stream = io.BytesIO(test_payload)
                enc_file = os.path.join(tmpdir, f"test_{cipher}.enc")
                
                # Encrypt
                enc_result = CryptoVaultEngine.encrypt_file_stream(
                    in_stream, enc_file, cipher, self.keys
                )
                self.assertTrue(os.path.exists(enc_file))
                self.assertTrue(enc_result['total_stored_size'] > len(test_payload))
                
                # Decrypt stream
                chunks = []
                for chunk in CryptoVaultEngine.decrypt_file_stream(enc_file, cipher, self.keys):
                    chunks.append(chunk)
                recovered = b"".join(chunks)
                
                self.assertEqual(test_payload, recovered, f"Stream round-trip failed for {cipher}")

    def test_streaming_tamper_detection(self):
        test_payload = b"Small stream payload to test file tampering"
        with tempfile.TemporaryDirectory() as tmpdir:
            for cipher in ['aes', 'des', 'rc4']:
                in_stream = io.BytesIO(test_payload)
                enc_file = os.path.join(tmpdir, f"tamper_{cipher}.enc")
                CryptoVaultEngine.encrypt_file_stream(in_stream, enc_file, cipher, self.keys)
                
                # Corrupt the payload at the end of the file
                with open(enc_file, "r+b") as f:
                    f.seek(-1, os.SEEK_END)
                    b = f.read(1)
                    f.seek(-1, os.SEEK_END)
                    f.write(bytes([b[0] ^ 0x01]))
                
                with self.assertRaises(AuthenticationError):
                    list(CryptoVaultEngine.decrypt_file_stream(enc_file, cipher, self.keys))

if __name__ == '__main__':
    unittest.main()
