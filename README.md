# bushizhongguoren-ki — AES-128 Assembly (AES_ASM Branch)

Hardware-accelerated AES-128-CBC encryption and decryption implemented in pure x86_64 assembly using Intel/AMD AES-NI vector instructions, wrapped for Python via `ctypes`.

## Features
- **Pure x86_64 Assembly (`aes_ni_x86_64.s`)**:
  - Intel AES-NI 10-round key expansion using `aeskeygenassist` and `aesimc`.
  - High-performance CBC mode encryption (`asm_aes128_cbc_encrypt`) using `aesenc` / `aesenclast`.
  - High-performance CBC mode decryption (`asm_aes128_cbc_decrypt`) using `aesdec` / `aesdeclast`.
  - Single-block helpers (`asm_aes128_encrypt_block` / `asm_aes128_decrypt_block`).
- **Python Ctypes Wrapper (`asm_crypto.py`)**:
  - Exposes `AsmCrypto.aes128_cbc_encrypt(data, key, iv)` and `AsmCrypto.aes128_cbc_decrypt(data, key, iv)`.
  - Bit-for-bit verified with standard cryptography (`PyCryptodome`).
- **Benchmark & Verification Suite (`test_and_benchmark_asm.py`)**:
  - Automated verification of round-trip encryption/decryption.
  - Multi-iteration throughput benchmarks (~690+ MB/s hardware throughput).

## Building the Shared Library
Compile the assembly sources into `libcrypto_asm.so`:
```bash
make -C crypto_asm
```

## Running Verification & Benchmark
```bash
python crypto_asm/test_and_benchmark_asm.py
```