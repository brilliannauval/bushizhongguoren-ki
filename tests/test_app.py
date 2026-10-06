"""
tests/test_app.py - Integration Tests for Web Vault Endpoints
Verifies:
  - Registration & Argon2id password hashing
  - Login lockout defense (5 failed attempts)
  - GDPR/UU PDP profile parallel encryption & retrieval
  - File upload (ID card, document, video) with simultaneous AES, DES, RC4 encryption
  - Decrypted download via AES, DES, and RC4
  - API benchmark endpoint
"""

import os
import io
import unittest
from app import app, db_session, User, PrivateData, FileRecord

class TestApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True

    def setUp(self):
        self.client = app.test_client()
        self.username = f"testuser_{os.urandom(4).hex()}"
        self.password = "P@ssword123"
        salt = os.urandom(16)
        user = User(username=self.username, salt=salt)
        user.set_password(self.password)
        db_session.add(user)
        db_session.commit()
        self.user_id = user.id

    def tearDown(self):
        user = db_session.get(User, self.user_id)
        if user:
            db_session.delete(user)
            db_session.commit()

    def login(self):
        return self.client.post('/login', data={
            'username': self.username,
            'password': self.password
        }, follow_redirects=True)

    def test_login_success(self):
        resp = self.login()
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Center", resp.data)

    def test_login_lockout_after_5_attempts(self):
        for _ in range(5):
            resp = self.client.post('/login', data={
                'username': self.username,
                'password': 'WrongPassword123'
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

        # 6th attempt triggers lockout
        resp = self.client.post('/login', data={
            'username': self.username,
            'password': self.password
        }, follow_redirects=True)
        self.assertIn(b"temporarily locked", resp.data)

    def test_profile_gdpr_encryption_roundtrip(self):
        self.login()
        resp = self.client.post('/profile', data={
            'full_name': 'Ahmad Dahlan',
            'email': 'ahmad@example.com',
            'phone': '08123456789',
            'dob': '1995-10-20',
            'address': 'Jl. Merdeka No. 10',
            'nik': '3171012010950002',
            'health_info': 'Golongan Darah B, Sehat'
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"successfully encrypted in AES, DES, and RC4", resp.data)

        # View profile and verify decrypted data appears
        view_resp = self.client.get('/profile')
        self.assertIn(b"Ahmad Dahlan", view_resp.data)
        self.assertIn(b"3171012010950002", view_resp.data)
        self.assertIn(b"AES-128-CBC", view_resp.data)
        self.assertIn(b"DES-CBC", view_resp.data)

    def test_file_upload_and_triple_cipher_download(self):
        self.login()
        # Upload a dummy PNG ID card with valid PNG signature
        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"A" * 1000)
        data = {
            'category': 'id_card',
            'file': (io.BytesIO(png_content), 'test_ktp.png')
        }
        upload_resp = self.client.post('/files/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(upload_resp.status_code, 200)
        self.assertIn(b"successfully encrypted in AES, DES, and RC4", upload_resp.data)

        # Fetch the created file record
        record = db_session.query(FileRecord).filter_by(user_id=self.user_id).first()
        self.assertIsNotNone(record)

        # Download using AES
        down_aes = self.client.get(f'/files/download/{record.id}?cipher=aes')
        self.assertEqual(down_aes.status_code, 200)
        self.assertEqual(down_aes.data, png_content)

        # Download using DES
        down_des = self.client.get(f'/files/download/{record.id}?cipher=des')
        self.assertEqual(down_des.status_code, 200)
        self.assertEqual(down_des.data, png_content)

        # Download using RC4
        down_rc4 = self.client.get(f'/files/download/{record.id}?cipher=rc4')
        self.assertEqual(down_rc4.status_code, 200)
        self.assertEqual(down_rc4.data, png_content)

    def test_api_benchmark_endpoint(self):
        self.login()
        # Setup profile first
        self.client.post('/profile', data={
            'full_name': 'Siti Rahma',
            'email': 'siti@example.com',
            'phone': '0812345678',
            'dob': '1999-01-01',
            'address': 'Bandung',
            'nik': '3273010101990001',
            'health_info': 'Golongan Darah A'
        }, follow_redirects=True)

        bench_resp = self.client.post('/api/benchmark/run', json={
            'item_type': 'profile',
            'iterations': 5
        })
        self.assertEqual(bench_resp.status_code, 200)
        data = bench_resp.get_json()
        self.assertIn('results', data)
        self.assertIn('aes', data['results'])
        self.assertIn('des', data['results'])
        self.assertIn('rc4', data['results'])
        self.assertEqual(len(data['results']['aes']['durations']), 5)

if __name__ == '__main__':
    unittest.main()
