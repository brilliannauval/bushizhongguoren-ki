"""
benchmark_cli.py - Command-Line Multi-Download Benchmark Suite
Automates running multi-iteration downloads (10 runs) across:
  - GDPR / UU PDP Personal Data Record
  - ID Card Image (2 MB)
  - Document (PDF, 5 MB)
  - Video File (50 MB)
Measures:
  - Running Time per iteration (ms)
  - Mean, Min, Max, Standard Deviation (ms)
  - Decryption Throughput (MB/s)
  - Ciphertext Size Expansion (%)
  - Shannon Entropy (bits/byte)
"""

import os
import io
import math
import time
import argparse
import tempfile
from typing import Dict, Any, List

from crypto_service import KeyManager, CryptoVaultEngine

def run_benchmarks(video_size_mb: int = 50, iterations: int = 10):
    print("================================================================================")
    print("      INFORMATION SECURITY (IFS) - CRYPTOGRAPHIC BENCHMARK SUITE (WEEK 4)       ")
    print(f"      Configurations: Iterations = {iterations}x | Max File Size = {video_size_mb} MB           ")
    print("================================================================================\n")

    salt = os.urandom(16)
    passphrase = "MasterStudentBenchmarkKey123!#"
    keys = KeyManager.derive_keys(passphrase, salt)

    # Prepare Test Payloads
    # 1. GDPR Private Data (Text, ~1 KB)
    gdpr_data = (
        "Name: Raden Mas Danang; NIK: 3175010203040005; Email: danang@vault.id; "
        "Phone: +6281298765432; Address: Jl. Diponegoro No. 88, Menteng, Jakarta Pusat; "
        "Health: Golongan Darah AB+, Tidak Memiliki Riwayat Alergi Berat, Vaksin Lengkap."
    ).encode('utf-8')

    # 2. ID Card Image (2 MB synthetic PNG)
    id_card_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(2 * 1024 * 1024 - 16)

    # 3. Document (5 MB synthetic PDF)
    doc_data = b"%PDF-1.7\n" + os.urandom(5 * 1024 * 1024 - 9)

    # 4. Video File (User-configured, default 50 MB synthetic MP4)
    video_size_bytes = video_size_mb * 1024 * 1024
    video_data = b"\x00\x00\x00\x18ftypmp42" + os.urandom(video_size_bytes - 12)

    categories = [
        ("GDPR Personal Data", gdpr_data, "memory"),
        ("ID Card Image", id_card_data, "file"),
        ("Document (PDF)", doc_data, "file"),
        (f"Video File ({video_size_mb} MB)", video_data, "file"),
    ]

    all_results = {}

    with tempfile.TemporaryDirectory() as tmpdir:
        for cat_name, raw_bytes, mode in categories:
            print(f"[*] Benchmarking: {cat_name} ({len(raw_bytes) / (1024*1024):.2f} MB)...")
            cat_results = {}

            for cipher in ['aes', 'des', 'rc4']:
                if mode == "memory":
                    # In-memory benchmark
                    enc_res = CryptoVaultEngine.encrypt_data(raw_bytes, cipher, keys)
                    ct = enc_res['ciphertext']
                    iv = enc_res['iv']
                    hmac_val = enc_res['hmac']
                    ct_size = len(ct)
                    entropy = enc_res['entropy']

                    durations = []
                    for _ in range(iterations):
                        t0 = time.perf_counter()
                        CryptoVaultEngine.decrypt_data(ct, cipher, iv, hmac_val, keys)
                        durations.append((time.perf_counter() - t0) * 1000.0)

                else:
                    # Stream file benchmark
                    enc_path = os.path.join(tmpdir, f"bench_{cipher}.enc")
                    in_stream = io.BytesIO(raw_bytes)
                    enc_res = CryptoVaultEngine.encrypt_file_stream(in_stream, enc_path, cipher, keys)
                    ct_size = enc_res['total_stored_size']
                    entropy = enc_res['entropy']

                    durations = []
                    for _ in range(iterations):
                        t0 = time.perf_counter()
                        for _ in CryptoVaultEngine.decrypt_file_stream(enc_path, cipher, keys):
                            pass
                        durations.append((time.perf_counter() - t0) * 1000.0)

                avg_d = sum(durations) / len(durations)
                min_d = min(durations)
                max_d = max(durations)
                var = sum((x - avg_d) ** 2 for x in durations) / len(durations)
                std_dev = math.sqrt(var)
                payload_mb = len(raw_bytes) / (1024 * 1024)
                throughput = payload_mb / (avg_d / 1000.0) if avg_d > 0 else 0
                expansion = ((ct_size - len(raw_bytes)) / len(raw_bytes)) * 100.0

                cat_results[cipher] = {
                    'avg_ms': avg_d,
                    'min_ms': min_d,
                    'max_ms': max_d,
                    'std_dev': std_dev,
                    'throughput_mbps': throughput,
                    'ciphertext_size': ct_size,
                    'expansion_pct': expansion,
                    'entropy': entropy
                }

            all_results[cat_name] = cat_results

    # Print Formatted Markdown Summary Table
    print("\n" + "=" * 80)
    print("                          EMPIRICAL RESULTS SUMMARY                             ")
    print("=" * 80)

    print("\n### Decryption Running Time & Throughput Comparison (10 Iterations Mean)")
    print("| Data Category | Plaintext Size | Cipher | Mean Time (ms) | Min / Max (ms) | Std Dev (ms) | Throughput (MB/s) | Ciphertext Size | Entropy |")
    print("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|")

    for cat_name, c_res in all_results.items():
        for cipher in ['aes', 'des', 'rc4']:
            info = c_res[cipher]
            cipher_label = "AES-128-CBC" if cipher == 'aes' else ("DES-CBC" if cipher == 'des' else "RC4 (ARC4)")
            size_str = f"{info['ciphertext_size'] / (1024*1024):.2f} MB" if info['ciphertext_size'] > 1024*1024 else f"{info['ciphertext_size']} B"
            print(
                f"| {cat_name} | {size_str} | **{cipher_label}** | {info['avg_ms']:.2f} ms | "
                f"{info['min_ms']:.2f} / {info['max_ms']:.2f} ms | ± {info['std_dev']:.2f} ms | "
                f"**{info['throughput_mbps']:.2f} MB/s** | {info['ciphertext_size']} B ({info['expansion_pct']:+.2f}%) | "
                f"{info['entropy']:.4f} |"
            )

    print("\n" + "=" * 80)
    return all_results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run Cryptographic Vault Multi-Download Benchmarks")
    parser.add_argument("--iterations", type=int, default=10, help="Number of download iterations (default: 10)")
    parser.add_argument("--video-size-mb", type=int, default=50, help="Size of video payload in MB (default: 50)")
    args = parser.parse_args()

    run_benchmarks(video_size_mb=args.video_size_mb, iterations=args.iterations)
