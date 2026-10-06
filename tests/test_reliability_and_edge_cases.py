"""
tests/test_reliability_and_edge_cases.py - Reliability & Defensive Boundary Test Suite

Covers:
  1. test_corrupted_database_row_null_and_truncated_fields
     - Injects Null full_name_enc, truncated JSON email_enc, invalid hex phone_enc, missing AES blocks.
     - Confirms HTTP 200 graceful handling with placeholders, preventing 500 crashes.
  2. test_aborted_upload_stream_cleans_up_orphaned_files
     - Simulates connection severed at 64 KB of a 200 KB stream in CryptoVaultEngine.
     - Confirms temporary and final files are cleaned up.
  3. test_aborted_upload_via_app_route_leaves_no_orphans
     - Simulates route-level failure on 2nd cipher pass (DES).
     - Confirms 0 orphaned files in upload folder and DB rollback.
  4. test_key_zeroization_and_memory_scoping
     - Audits module globals and classes for persistent master/derived keys.
     - Verifies in-place mutable memory zeroization (bytearray).
  5. test_restricted_upload_directory_permissions_error_handling
     - Simulates PermissionError on upload directory.
     - Verifies generic sanitized message and zero system path disclosure.
"""

import os
import io
import json
import unittest
from unittest.mock import patch

from app import app, db_session, User, PrivateData, FileRecord, get_user_keys
from crypto_service import CryptoVaultEngine, KeyManager, zeroize_buffer
import crypto_service
import app as app_module
import security as security_module

class TestReliabilityAndEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True

    def setUp(self):
        self.client = app.test_client()
        self.username = f"rel_user_{os.urandom(4).hex()}"
        self.password = "SecurePass#2026"
        salt = os.urandom(16)
        user = User(username=self.username, salt=salt)
        user.set_password(self.password)
        db_session.add(user)
        db_session.commit()
        self.user_id = user.id

    def tearDown(self):
        user = db_session.get(User, self.user_id)
        if user:
            # Delete any user files
            for f in user.files:
                for fname in [f.aes_filename, f.des_filename, f.rc4_filename]:
                    p = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                    if os.path.exists(p):
                        try:
                            os.remove(p)
                        except OSError:
                            pass
            db_session.delete(user)
            db_session.commit()

    def login(self):
        return self.client.post('/login', data={
            'username': self.username,
            'password': self.password
        }, follow_redirects=True)

    def test_corrupted_database_row_null_and_truncated_fields(self):
        """Simulates malformed DB state: null, truncated JSON, invalid hex, and missing AES blocks."""
        self.login()

        user = db_session.get(User, self.user_id)
        priv = user.private_data
        if not priv:
            priv = PrivateData(user_id=user.id)
            db_session.add(priv)

        # 1. Null field
        priv.full_name_enc = None
        # 2. Truncated JSON
        priv.email_enc = '{"aes": {"ct": "a1b2", "iv": "c3d4"'
        # 3. Invalid hex
        priv.phone_enc = json.dumps({
            'aes': {'ct': 'not_a_hex_string_zzz', 'iv': '1234', 'hmac': '5678', 'entropy': 0.0, 'duration_ms': 0.0}
        })
        # 4. Missing AES block entirely (only DES present)
        priv.address_enc = json.dumps({
            'des': {'ct': 'deadbeef', 'iv': '0011223344556677', 'hmac': '8899', 'entropy': 0.0, 'duration_ms': 0.0}
        })
        priv.dob_enc = None
        priv.nik_enc = None
        priv.health_info_enc = None
        db_session.commit()

        # Request profile page; must render HTTP 200 without crashing on template line 131
        resp = self.client.get('/profile')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Corrupted Data", resp.data)
        self.assertIn(b"Full Name", resp.data)

    def test_aborted_upload_stream_cleans_up_orphaned_files(self):
        """Simulates socket disconnection at 64 KB of 200 KB in CryptoVaultEngine."""
        class AbortedStream(io.BytesIO):
            def __init__(self, data, fail_after_bytes):
                super().__init__(data)
                self.fail_after_bytes = fail_after_bytes
                self.read_so_far = 0

            def read(self, size=-1):
                if self.read_so_far >= self.fail_after_bytes:
                    raise ConnectionResetError("Client aborted connection during stream")
                chunk = super().read(size)
                self.read_so_far += len(chunk)
                return chunk

        payload = b"X" * (200 * 1024)
        stream = AbortedStream(payload, fail_after_bytes=64 * 1024)
        out_path = os.path.join(app.config['UPLOAD_FOLDER'], "test_engine_abort.enc")
        tmp_path = out_path + ".tmp"

        keys = KeyManager.derive_keys(self.password, os.urandom(16))

        with self.assertRaises(ConnectionResetError):
            CryptoVaultEngine.encrypt_file_stream(stream, out_path, 'aes', keys)

        # Neither the final file nor the temporary file should linger
        self.assertFalse(os.path.exists(out_path), "Final .enc file was not cleaned up after abort")
        self.assertFalse(os.path.exists(tmp_path), "Temporary .tmp file was not cleaned up after abort")

    def test_aborted_upload_via_app_route_leaves_no_orphans(self):
        """Simulates multi-pass upload failing on 2nd cipher pass (DES); checks disk and DB."""
        self.login()

        # Capture file list before upload
        before_files = set(os.listdir(app.config['UPLOAD_FOLDER']))

        orig_encrypt = CryptoVaultEngine.encrypt_file_stream

        def faulty_encrypt(in_stream, out_path, cipher_name, keys):
            if cipher_name == 'des':
                raise IOError("Simulated network/disk crash during DES cipher pass")
            return orig_encrypt(in_stream, out_path, cipher_name, keys)

        with patch('crypto_service.CryptoVaultEngine.encrypt_file_stream', side_effect=faulty_encrypt):
            data = {
                'category': 'document',
                'file': (io.BytesIO(b"%PDF-1.4\n" + b"A" * 10000), 'crash_test.pdf')
            }
            resp = self.client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Upload failed", resp.data)

        # Verify disk has zero orphaned files from this upload
        after_files = set(os.listdir(app.config['UPLOAD_FOLDER']))
        self.assertEqual(before_files, after_files, f"Orphaned files found: {after_files - before_files}")

        # Verify database has no orphaned record
        record = db_session.query(FileRecord).filter_by(user_id=self.user_id, original_filename='crash_test.pdf').first()
        self.assertIsNone(record, "Database committed a partial file record despite upload crash")

    def test_key_zeroization_and_memory_scoping(self):
        """Audits module namespaces for key persistence and tests mutable buffer zeroization."""
        # 1. Inspect globals of crypto modules
        for mod in (crypto_service, app_module, security_module):
            g = vars(mod)
            for sensitive_key in ['aes_key', 'des_key', 'rc4_key', 'hmac_key', 'master_password']:
                self.assertNotIn(sensitive_key, g, f"Sensitive key variable '{sensitive_key}' found in module {mod.__name__} globals")

        # 2. Inspect KeyManager and CryptoVaultEngine class attributes
        self.assertFalse(hasattr(KeyManager, 'aes_key'))
        self.assertFalse(hasattr(CryptoVaultEngine, 'aes_key'))
        self.assertFalse(hasattr(CryptoVaultEngine, 'master_key'))

        # 3. Test in-place zeroization of mutable memory buffer
        plaintext = bytearray(b"super_secret_decrypted_patient_data_12345")
        original_len = len(plaintext)
        CryptoVaultEngine.zeroize_buffer(plaintext)

        self.assertEqual(len(plaintext), original_len)
        self.assertTrue(all(b == 0 for b in plaintext), "Buffer was not zeroized to 0x00")

    def test_restricted_upload_directory_permissions_error_handling(self):
        """Simulates PermissionError on upload directory write access and verifies path masking."""
        self.login()

        with patch('crypto_service.CryptoVaultEngine.encrypt_file_stream', side_effect=PermissionError("[Errno 13] Permission denied: '/home/kali/Downloads/Week4/uploads/secret.enc'")):
            data = {
                'category': 'document',
                'file': (io.BytesIO(b"%PDF-1.4\n" + b"B" * 5000), 'perm_test.pdf')
            }
            resp = self.client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

            # Check that generic notification is present
            self.assertIn(b"Storage error: Upload directory permission denied. Please contact system administrator.", resp.data)

            # Check that internal system path strings are strictly masked
            self.assertNotIn(b"/home/kali", resp.data)
            self.assertNotIn(b"/home/seannd", resp.data)
            self.assertNotIn(b"secret.enc", resp.data)
            self.assertNotIn(b"Permission denied: '", resp.data)

if __name__ == '__main__':
    unittest.main()
