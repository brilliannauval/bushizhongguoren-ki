# Secure Multi-Cipher Web Vault (AES-128-CBC, DES-CBC, RC4)
**Information Security (IfS) — Week 4 Lab Assignment 1**

An enterprise-grade, zero-knowledge cryptographic web vault implementing parallel encryption across **AES-128-CBC**, **DES-CBC**, and **RC4**, backed by **hardware-accelerated x86_64 GNU Assembly (Intel/AMD AES-NI)**, a 5-layer upload defense architecture, and GDPR/UU PDP personal data compliance.

---

## 📚 Complete Project Documentation & Wiki
For the full architectural manual, security defense proofs, mathematical specifications, and benchmarks, see:
👉 **[`WIKI_DOCUMENTATION.md`](file:///home/seannd/Code/IfS/Week4/WIKI_DOCUMENTATION.md)**

For the academic report with multi-iteration empirical performance tables and statutory privacy mapping, see:
👉 **[`REPORT_ANALYSIS.md`](file:///home/seannd/Code/IfS/Week4/REPORT_ANALYSIS.md)**

---

## 🚀 Key Highlights

1. **Hardware-Accelerated Cryptography (`crypto_asm/`)**:
   - Pure x86_64 Assembly implementation of AES-128-CBC using Intel/AMD AES-NI vector instructions (`aesenc`, `aesdec`, `aeskeygenassist`).
   - Hand-crafted 64-bit RC4 stream cipher in pure assembly (`rc4_x86_64.s`).
   - Native 64-bit Feistel DES engine in assembly/C (`des_x86_64.s`).
   - High-performance Python FFI bridge via `ctypes` (`asm_crypto.py`).
   - Delivers over **1,200 MB/s** throughput on hardware AES-NI.

2. **GDPR (EU) & UU PDP (Indonesia No. 27/2022) Privacy Compliance**:
   - Secure encrypted database storage for General (Name, Email, Phone, DOB, Address) and Sensitive (NIK/KTP, Medical) personal identity data.
   - Interactive technical inspector rendering raw hex ciphertexts, IVs, HMACs, and Shannon entropy scores.

3. **50 MB Multimedia Vault with In-Browser Playback**:
   - Supports ID Card images, Documents (PDF/DOCX/XLSX), and Videos (up to 50 MB).
   - In-browser image preview modals and native HTML5 video player streaming decrypted MP4 chunks.
   - 5-Layer upload defense-in-depth blocking webshells, double extensions (`.php.docx`), and trojan OpenXML packages.

4. **Hardened Penetration Testing Defense**:
   - **Encrypt-then-MAC (HMAC-SHA256)** verified in constant time to neutralize CBC padding oracle attacks.
   - **Argon2id** password hashing with 5-attempt automatic 15-minute account lockout.
   - Server-side ephemeral key vault (CWE-312), sliding-window rate limiting, and strict CSP headers.

---

## ⚡ Quick Start

### 1. Build the Native Assembly Engine
```bash
make -C crypto_asm
```

### 2. Run the DevSecOps Verification Pipeline (24 Tests Passing)
```bash
./audit_pipeline.sh
```

### 3. Launch the Web Application
```bash
source venv/bin/activate
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.