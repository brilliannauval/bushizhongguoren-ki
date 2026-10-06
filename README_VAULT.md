# Secure Multi-Cipher Web Vault (AES, DES, RC4) & Cryptographic Lab

**Course:** Information Security (IfS) — Week 4 Assignment 1  
**Directory:** `IfS/Week4/`  

---

## Quick Start

### 1. Activate Environment & Run Application
```bash
cd /home/seannd/Code/IfS/Week4
source venv/bin/activate
python app.py
```
Open your browser at `http://127.0.0.1:5000/`.

### 2. Run Automated Penetration Testing & Defense Audit
Simulates lecturer attack vectors (SQL Injection, XSS, IDOR, Path Traversal, Webshells, Padding Oracle, Brute-Force lockout):
```bash
python security_audit_test.py
```

### 3. Run Multi-Download Benchmarks (CLI)
Runs 10 download iterations across GDPR profile, ID Card, Document, and 50 MB Video:
```bash
python benchmark_cli.py --iterations 10 --video-size-mb 50
```

### 4. Build & Benchmark the x86_64 Assembly Module
Compiles `rc4_x86_64.s` and `aes_ni_x86_64.s` into `libcrypto_asm.so` and benchmarks against C-extensions:
```bash
make -C crypto_asm
python crypto_asm/test_and_benchmark_asm.py
```

---

## Key Features

1. **GDPR / UU PDP Private Data Protection:**
   - Compliant with EU GDPR Art. 4 & 9 and Indonesian UU PDP No. 27/2022 Pasal 4.
   - Encrypted in parallel with **AES-128-CBC**, **DES-CBC**, and **RC4**.
   - Technical inspector reveals raw ciphertexts, IVs, HMACs, and Shannon entropy.

2. **50 MB Multimedia Vault:**
   - Supports ID Card images, Documents (PDF/DOC/XLS), and Videos (up to 50 MB).
   - Buffered 64 KB chunk streaming ensures $O(1)$ memory consumption.
   - Magic-byte file header validation blocks malicious webshells.
   - Decrypted in-browser preview for ID Cards and Video streaming.
   - Decrypted download selector (AES, DES, or RC4).

3. **Multi-Download Benchmark Suite:**
   - Measures running time across 1x, 5x, and 10x download runs.
   - Interactive live Chart.js graphs (Latency, Iteration Variance, Throughput MB/s).
   - Generates empirical tables for mean, min, max, and standard deviation.

4. **Hardened Security Architecture:**
   - **Encrypt-then-MAC (HMAC-SHA256)** checked in constant time to neutralize Padding Oracle attacks.
   - **Argon2id** password hashing with 5-attempt automatic lockout for 15 minutes.
   - Strict CSRF protection and CSP HTTP security headers.
   - IDOR prevention ensuring strict session user ownership.
