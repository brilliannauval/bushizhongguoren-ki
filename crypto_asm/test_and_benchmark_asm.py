"""
test_and_benchmark_asm.py - Low-Level Cryptography Verification & Benchmark Suite
Verifies and benchmarks native low-level implementations vs PyCryptodome:
  1. AES-128-CBC: Pure x86_64 Assembly with Hardware AES-NI Instructions
  2. RC4: x86_64 Hand-crafted Assembly
  3. DES-CBC: Native 64-bit Feistel Engine (FIPS 46-3)
  4. Performance comparisons across 10 MB payloads
"""

import time
import os
import sys

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad, unpad

from crypto_asm.asm_crypto import AsmCrypto

def run_test_and_benchmark():
    print("================================================================================")
    print("        LOW-LEVEL NATIVE & ASSEMBLY CRYPTOGRAPHY VERIFICATION & BENCHMARK       ")
    print("================================================================================\n")

    # =========================================================================
    # PART 1: AES-128-CBC (x86_64 Hardware AES-NI Assembly) Verification
    # =========================================================================
    print("[1] AES-128-CBC (x86_64 Hardware AES-NI Assembly):")
    aes_key = b"16ByteSecretKey!"  # 16 bytes (128-bit key)
    aes_iv = b"16ByteInitialIV!"   # 16 bytes
    plaintext_aes = b"Confidential GDPR Data: NIK 3175010203040005, Name: Antigravity Vault" * 10
    padded_aes = pad(plaintext_aes, 16)

    asm_aes_ct = AsmCrypto.aes128_cbc_encrypt(padded_aes, aes_key, aes_iv)
    pyc_aes = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
    pyc_aes_ct = pyc_aes.encrypt(padded_aes)

    if asm_aes_ct == pyc_aes_ct:
        print("  -> SUCCESS: Assembly AES-128-CBC output matches PyCryptodome bit-for-bit!")
    else:
        print("  -> ERROR: Mismatch between Assembly AES-128-CBC and PyCryptodome!")
        return False

    asm_aes_recovered = AsmCrypto.aes128_cbc_decrypt(asm_aes_ct, aes_key, aes_iv)
    if unpad(asm_aes_recovered, 16) == plaintext_aes:
        print("  -> SUCCESS: Assembly AES-128-CBC round-trip decryption recovered original plaintext!")
    else:
        print("  -> ERROR: Assembly AES-128-CBC decryption failed.")
        return False

    # =========================================================================
    # PART 2: RC4 (x86_64 Assembly) Verification & Benchmark
    # =========================================================================
    print("\n[2] RC4 Stream Cipher (x86_64 Hand-Crafted Assembly):")
    rc4_key = b"AssemblySecretK!"  # 16 bytes
    plaintext_rc4 = b"This message is encrypted with hand-crafted x86_64 assembly language!" * 10

    asm_rc4_ct = AsmCrypto.rc4_encrypt(plaintext_rc4, rc4_key)
    pyc_rc4 = ARC4.new(rc4_key)
    pyc_rc4_ct = pyc_rc4.encrypt(plaintext_rc4)

    if asm_rc4_ct == pyc_rc4_ct:
        print("  -> SUCCESS: Assembly RC4 output matches PyCryptodome bit-for-bit!")
    else:
        print("  -> ERROR: Mismatch between Assembly RC4 and PyCryptodome!")
        return False

    asm_rc4_recovered = AsmCrypto.rc4_encrypt(asm_rc4_ct, rc4_key)
    if asm_rc4_recovered == plaintext_rc4:
        print("  -> SUCCESS: Assembly RC4 round-trip decryption recovered original plaintext!")
    else:
        print("  -> ERROR: Assembly RC4 decryption failed.")
        return False

    # =========================================================================
    # PART 3: DES-CBC (Native 64-bit Feistel Engine) Verification & Benchmark
    # =========================================================================
    print("\n[3] DES-CBC Block Cipher (Native 64-bit Feistel Engine, Non-ECB Mode):")
    des_key = b"8ByteKey"  # 8 bytes (56-bit effective)
    des_iv = b"8Byte_IV"   # 8 bytes
    raw_des_text = b"Confidential National ID NIK: 3175010203040005 & Banking Record"
    padded_des = pad(raw_des_text, 8)

    native_des_ct = AsmCrypto.des_cbc_encrypt(padded_des, des_key, des_iv)
    pyc_des = DES.new(des_key, DES.MODE_CBC, iv=des_iv)
    pyc_des_ct = pyc_des.encrypt(padded_des)

    if native_des_ct == pyc_des_ct:
        print("  -> SUCCESS: Native DES-CBC output matches PyCryptodome bit-for-bit!")
    else:
        print("  -> ERROR: Mismatch between Native DES and PyCryptodome!")
        return False

    native_des_dec = AsmCrypto.des_cbc_decrypt(native_des_ct, des_key, des_iv)
    if unpad(native_des_dec, 8) == raw_des_text:
        print("  -> SUCCESS: Native DES-CBC round-trip decryption recovered original plaintext!")
    else:
        print("  -> ERROR: Native DES-CBC decryption failed.")
        return False

    # =========================================================================
    # PART 4: Empirical Throughput Benchmark (10 MB Payload, 5 Iterations)
    # =========================================================================
    print("\n[4] Empirical Throughput Benchmark (10 MB Payload, 5 Iterations):")
    large_payload = os.urandom(10 * 1024 * 1024)
    iterations = 5

    # 4.1 AES-128 Benchmarks
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = AsmCrypto.aes128_cbc_encrypt(large_payload, aes_key, aes_iv)
    t_asm_aes = time.perf_counter() - t0
    asm_aes_tp = (10 * iterations) / t_asm_aes

    t0 = time.perf_counter()
    for _ in range(iterations):
        c = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        _ = c.encrypt(large_payload)
    t_pyc_aes = time.perf_counter() - t0
    pyc_aes_tp = (10 * iterations) / t_pyc_aes

    # 4.2 RC4 Benchmarks
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = AsmCrypto.rc4_encrypt(large_payload, rc4_key)
    t_asm_rc4 = time.perf_counter() - t0
    asm_rc4_tp = (10 * iterations) / t_asm_rc4

    t0 = time.perf_counter()
    for _ in range(iterations):
        c = ARC4.new(rc4_key)
        _ = c.encrypt(large_payload)
    t_pyc_rc4 = time.perf_counter() - t0
    pyc_rc4_tp = (10 * iterations) / t_pyc_rc4

    # 4.3 DES-CBC Benchmarks
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = AsmCrypto.des_cbc_encrypt(large_payload, des_key, des_iv)
    t_native_des = time.perf_counter() - t0
    native_des_tp = (10 * iterations) / t_native_des

    t0 = time.perf_counter()
    for _ in range(iterations):
        c = DES.new(des_key, DES.MODE_CBC, iv=des_iv)
        _ = c.encrypt(large_payload)
    t_pyc_des = time.perf_counter() - t0
    pyc_des_tp = (10 * iterations) / t_pyc_des

    print("\n" + "-" * 80)
    print("                     BENCHMARK COMPARISON TABLE                         ")
    print("-" * 80)
    print(f"| Algorithm   | Implementation           | Mean Latency (ms) | Throughput (MB/s) |")
    print(f"|:------------|:-------------------------|:-----------------:|:-----------------:|")
    print(f"| **AES-128** | x86_64 AES-NI Assembly   | {t_asm_aes*1000/iterations:14.2f} ms | {asm_aes_tp:14.2f} MB/s |")
    print(f"| **AES-128** | PyCryptodome (C/Asm)     | {t_pyc_aes*1000/iterations:14.2f} ms | {pyc_aes_tp:14.2f} MB/s |")
    print(f"| **RC4**     | x86_64 Hand Assembly     | {t_asm_rc4*1000/iterations:14.2f} ms | {asm_rc4_tp:14.2f} MB/s |")
    print(f"| **RC4**     | PyCryptodome (C/Asm)     | {t_pyc_rc4*1000/iterations:14.2f} ms | {pyc_rc4_tp:14.2f} MB/s |")
    print(f"| **DES**     | Native 64-bit Feistel    | {t_native_des*1000/iterations:14.2f} ms | {native_des_tp:14.2f} MB/s |")
    print(f"| **DES**     | PyCryptodome (Optimized) | {t_pyc_des*1000/iterations:14.2f} ms | {pyc_des_tp:14.2f} MB/s |")
    print("-" * 80 + "\n")

    return True

if __name__ == "__main__":
    success = run_test_and_benchmark()
    sys.exit(0 if success else 1)
