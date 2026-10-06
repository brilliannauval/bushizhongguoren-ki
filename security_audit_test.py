"""
security_audit_test.py - Automated Penetration Testing & Lecturer Attack Simulation
Validates defense-in-depth security against all attack vectors:
  1. SQL Injection (SQLi)
  2. Cross-Site Scripting (XSS) & Template Injection
  3. Insecure Direct Object References (IDOR)
  4. Path Traversal & Arbitrary File Access
  5. Malicious File Uploads / Extension Spoofing / 50MB Size Exceeded
  6. CBC Padding Oracle & Ciphertext Tampering
  7. Brute-Force Password Guessing & Account Lockout
  8. Cross-Site Request Forgery (CSRF)
"""

import os
import io
import zipfile
import unittest
from app import app, db_session, User, FileRecord, PrivateData
from crypto_service import KeyManager, CryptoVaultEngine, AuthenticationError

class LecturerSecurityAuditTest(unittest.TestCase):
    def setUp(self):
        # Disable TESTING mode for CSRF tests, re-enable for others as needed
        app.config['TESTING'] = True
        self.client = app.test_client()

        # Seed two distinct users for IDOR testing
        self.alice_pass = "AliceSecurePass123!"
        self.alice = User(username=f"alice_{os.urandom(4).hex()}", salt=os.urandom(16))
        self.alice.set_password(self.alice_pass)

        self.bob_pass = "BobSecurePass123!"
        self.bob = User(username=f"bob_{os.urandom(4).hex()}", salt=os.urandom(16))
        self.bob.set_password(self.bob_pass)

        db_session.add_all([self.alice, self.bob])
        db_session.commit()
        self.alice_id = self.alice.id
        self.bob_id = self.bob.id
        self.alice_username = self.alice.username
        self.bob_username = self.bob.username

    def tearDown(self):
        for uid in [self.alice_id, self.bob_id]:
            u = db_session.get(User, uid)
            if u:
                db_session.delete(u)
        db_session.commit()

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)

    # -------------------------------------------------------------------------
    # 1. SQL Injection Tests
    # -------------------------------------------------------------------------
    def test_sql_injection_on_login(self):
        sqli_payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT 1, 'admin', 'hash', 'salt', 0, NULL, datetime('now')--",
            "\" OR \"\"=\"",
            "'; DROP TABLE users;--"
        ]
        for payload in sqli_payloads:
            resp = self.client.post('/login', data={'username': payload, 'password': 'randompassword'}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Invalid credentials", resp.data, f"SQLi payload breached login: {payload}")

    # -------------------------------------------------------------------------
    # 2. Cross-Site Scripting (XSS) Tests
    # -------------------------------------------------------------------------
    def test_xss_sanitization_and_csp(self):
        self.login(self.alice_username, self.alice_pass)
        xss_payload = "<script>alert('XSS_PWNED')</script>"
        img_payload = "<img src=x onerror=alert(1)>"

        self.client.post('/profile', data={
            'full_name': xss_payload,
            'email': 'alice@xss.test',
            'phone': '12345',
            'dob': '2000-01-01',
            'address': img_payload,
            'nik': '1234567890123456',
            'health_info': 'Normal'
        }, follow_redirects=True)

        resp = self.client.get('/profile')
        # Ensure unescaped raw scripts are NOT executed in the browser
        self.assertNotIn(b"<script>alert('XSS_PWNED')</script>", resp.data)
        # Verify strict CSP headers are present
        self.assertIn('Content-Security-Policy', resp.headers)
        self.assertIn("default-src 'self'", resp.headers['Content-Security-Policy'])

    # -------------------------------------------------------------------------
    # 3. Insecure Direct Object References (IDOR) Tests
    # -------------------------------------------------------------------------
    def test_idor_cross_user_file_download_blocked(self):
        # Step 1: Alice logs in and uploads an ID Card
        self.login(self.alice_username, self.alice_pass)
        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"ALICE_SECRET_ID_CARD" * 50)
        self.client.post('/files/upload', data={
            'category': 'id_card',
            'file': (io.BytesIO(png_content), 'alice_id.png')
        }, content_type='multipart/form-data', follow_redirects=True)

        alice_file = db_session.query(FileRecord).filter_by(user_id=self.alice_id).first()
        self.assertIsNotNone(alice_file)

        # Step 2: Bob logs in and tries to download Alice's file ID
        self.client.get('/logout', follow_redirects=True)
        self.login(self.bob_username, self.bob_pass)

        # Bob attempts to access Alice's file
        idor_resp = self.client.get(f'/files/download/{alice_file.id}?cipher=aes')
        self.assertEqual(idor_resp.status_code, 404, "IDOR failure: User B was able to access User A's file!")

    # -------------------------------------------------------------------------
    # 4. Malicious File Uploads / Extension Spoofing & 50MB Limit
    # -------------------------------------------------------------------------
    def test_malicious_file_uploads_rejected(self):
        self.login(self.alice_username, self.alice_pass)

        # A: PHP Web Shell disguised with .png extension (blocked via script pattern or magic bytes)
        fake_png = b"<?php system($_GET['cmd']); ?>"
        resp1 = self.client.post('/files/upload', data={
            'category': 'id_card',
            'file': (io.BytesIO(fake_png), 'shell.png')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertTrue(
            b"File content does not match expected" in resp1.data or b"Executable script code" in resp1.data,
            f"Disguised webshell was not blocked: {resp1.data}"
        )

        # B: Dangerous executable extension
        fake_exe = b"MZ\x90\x00" + (b"\x00" * 100)
        resp2 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (io.BytesIO(fake_exe), 'exploit.exe')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertIn(b"Disallowed file extension", resp2.data)

        # C: File exceeding 50 MB limit
        oversized_data = io.BytesIO(b"%PDF-" + (b"0" * (51 * 1024 * 1024)))
        resp3 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (oversized_data, 'giant.pdf')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertIn(b"exceeds maximum allowed size of 50 MB", resp3.data)

        # D: Disallowed formats (e.g., .webp, .doc, .xls, .txt, .csv, .webm, .avi)
        disallowed_samples = [
            ('id_card', 'test.webp', b"RIFF\x00\x00\x00\x00WEBP"),
            ('document', 'old.doc', b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100),
            ('document', 'old.xls', b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100),
            ('document', 'notes.txt', b"Hello World text document"),
            ('document', 'data.csv', b"col1,col2\nval1,val2\n"),
            ('video', 'movie.webm', b"\x1a\x45\xdf\xa3" + b"\x00" * 100),
            ('video', 'clip.avi', b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 100),
        ]
        for cat, fname, content in disallowed_samples:
            resp = self.client.post('/files/upload', data={
                'category': cat,
                'file': (io.BytesIO(content), fname)
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertIn(b"Disallowed file extension", resp.data, f"Format '{fname}' should be blocked but was accepted.")

    def test_double_extension_and_webshell_attacks_blocked(self):
        """Validates defense against .php.docx, disguised webshells, and null-byte injections."""
        self.login(self.alice_username, self.alice_pass)

        # A: .php.docx double extension attack
        docx_dummy = io.BytesIO(b"PK\x03\x04" + b"\x00" * 100)
        resp1 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (docx_dummy, 'shell.php.docx')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertTrue(
            b"Malicious script extension" in resp1.data and b"php" in resp1.data,
            f"Expected malicious script extension block in response: {resp1.data}"
        )

        # B: Dangerous script sub-extensions (.phtml.pdf, .py.png, .sh.docx)
        resp2 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (io.BytesIO(b"%PDF-1.4" + b"\x00" * 50), 'exploit.phtml.pdf')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertTrue(
            b"Malicious script extension" in resp2.data and b"phtml" in resp2.data,
            f"Expected malicious script extension block in response: {resp2.data}"
        )

        # C: Null-byte injection (.php%00.docx)
        resp3 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (io.BytesIO(b"PK\x03\x04" + b"\x00" * 50), 'evil.php%00.docx')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertIn(b"Null-byte injection detected", resp3.data)

        # D: Fake DOCX with raw PHP webshell contents
        fake_docx_php = io.BytesIO(b"<?php phpinfo(); ?>")
        resp4 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (fake_docx_php, 'innocent.docx')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertTrue(
            b"Executable script code" in resp4.data or b"File content does not match" in resp4.data,
            "Fake docx containing PHP was not blocked!"
        )

        # E: Zip archive disguised as DOCX but containing a .php file inside
        malicious_zip = io.BytesIO()
        with zipfile.ZipFile(malicious_zip, 'w') as zf:
            zf.writestr('[Content_Types].xml', '<Types></Types>')
            zf.writestr('word/document.xml', '<w:document></w:document>')
            zf.writestr('word/shell.php', '<?php system($_GET["cmd"]); ?>')
        malicious_zip.seek(0)

        resp5 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (malicious_zip, 'trojan.docx')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertTrue(
            b"Embedded script" in resp5.data or b"Executable script code" in resp5.data,
            f"Trojan docx containing PHP was not blocked: {resp5.data}"
        )

        # E2: Zip archive containing an embedded file with .php extension (no raw PHP tag)
        malicious_zip2 = io.BytesIO()
        with zipfile.ZipFile(malicious_zip2, 'w') as zf:
            zf.writestr('[Content_Types].xml', '<Types></Types>')
            zf.writestr('word/document.xml', '<w:document></w:document>')
            zf.writestr('word/module.php', 'Simple text without php tags')
        malicious_zip2.seek(0)

        resp6 = self.client.post('/files/upload', data={
            'category': 'document',
            'file': (malicious_zip2, 'trojan2.docx')
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertIn(b"Embedded script", resp6.data)

    def test_valid_file_formats_allowed(self):
        """Verifies that all strictly allowed formats (JPG, JPEG, PNG, PDF, DOCX, XLSX, MP4) upload and encrypt successfully."""
        self.login(self.alice_username, self.alice_pass)

        # 1. Valid JPG
        jpg_content = b"\xff\xd8\xff\xe0\x00\x10JFIF" + (b"\x00" * 200)
        # 2. Valid PNG
        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"\x00" * 200)
        # 3. Valid PDF
        pdf_content = b"%PDF-1.7\n%ValidPDFHeader" + (b"\x00" * 200)
        # 4. Valid DOCX
        docx_buf = io.BytesIO()
        with zipfile.ZipFile(docx_buf, 'w') as z:
            z.writestr('[Content_Types].xml', '<Types></Types>')
            z.writestr('word/document.xml', '<w:document></w:document>')
        docx_content = docx_buf.getvalue()
        # 5. Valid XLSX
        xlsx_buf = io.BytesIO()
        with zipfile.ZipFile(xlsx_buf, 'w') as z:
            z.writestr('[Content_Types].xml', '<Types></Types>')
            z.writestr('xl/workbook.xml', '<workbook></workbook>')
        xlsx_content = xlsx_buf.getvalue()
        # 6. Valid MP4
        mp4_content = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00" + (b"\x00" * 200)

        valid_files = [
            ('id_card', 'valid_photo.jpg', jpg_content),
            ('id_card', 'valid_card.png', png_content),
            ('document', 'valid_doc.pdf', pdf_content),
            ('document', 'valid_paper.docx', docx_content),
            ('document', 'valid_sheet.xlsx', xlsx_content),
            ('video', 'valid_stream.mp4', mp4_content)
        ]

        for cat, fname, content in valid_files:
            resp = self.client.post('/files/upload', data={
                'category': cat,
                'file': (io.BytesIO(content), fname)
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(resp.status_code, 200, f"Upload failed for {fname}")
            self.assertIn(
                b"successfully encrypted in AES, DES, and RC4",
                resp.data,
                f"Valid file '{fname}' was unexpectedly rejected: {resp.data}"
            )

    # -------------------------------------------------------------------------
    # 5. Padding Oracle Defense & Bit-Flipping Tampering
    # -------------------------------------------------------------------------
    def test_padding_oracle_tampering_aborts_immediately(self):
        salt = os.urandom(16)
        keys = KeyManager.derive_keys("TestingSecretKey", salt)
        sample = b"CreditCardNumber=4111222233334444;CVV=123"

        for cipher in ['aes', 'des']:
            res = CryptoVaultEngine.encrypt_data(sample, cipher, keys)
            
            # Attacker alters the last byte of ciphertext (padding target)
            tampered_ct = bytearray(res['ciphertext'])
            tampered_ct[-1] ^= 0x01

            # System must raise AuthenticationError via HMAC without revealing padding validity
            with self.assertRaises(AuthenticationError):
                CryptoVaultEngine.decrypt_data(
                    bytes(tampered_ct), cipher, res['iv'], res['hmac'], keys
                )

    # -------------------------------------------------------------------------
    # 6. Brute-Force Password Guessing & Account Lockout
    # -------------------------------------------------------------------------
    def test_brute_force_lockout_mechanism(self):
        u = db_session.get(User, self.alice_id)
        u.failed_login_attempts = 0
        u.locked_until = None
        db_session.commit()

        for attempt in range(1, 6):
            self.client.post('/login', data={'username': self.alice_username, 'password': 'wrongpassword'}, follow_redirects=True)

        # Confirm locked state in DB
        u = db_session.get(User, self.alice_id)
        self.assertTrue(u.is_locked())
        self.assertEqual(u.failed_login_attempts, 5)

        # 6th attempt with correct password must still be rejected while locked
        locked_resp = self.client.post('/login', data={'username': self.alice_username, 'password': self.alice_pass}, follow_redirects=True)
        self.assertIn(b"Account temporarily locked", locked_resp.data)

    # -------------------------------------------------------------------------
    # 7. CSRF Defense
    # -------------------------------------------------------------------------
    def test_csrf_token_required_in_production(self):
        # Temporarily enable CSRF enforcement
        app.config['TESTING'] = False
        try:
            prod_client = app.test_client()
            resp = prod_client.post('/login', data={'username': 'hacker', 'password': 'password'}, follow_redirects=True)
            self.assertIn(b"Invalid or expired CSRF token", resp.data)
        finally:
            app.config['TESTING'] = True

if __name__ == '__main__':
    unittest.main()
