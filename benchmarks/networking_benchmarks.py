"""Benchmarks for networking and encryption performance."""

import time

from securesync.infrastructure.crypto.pyca_crypto import AesGcmCipher, ChaCha20Cipher


def benchmark_encryption() -> None:
    """Benchmark AES-GCM vs ChaCha20-Poly1305 throughput."""
    data = os.urandom(1024 * 1024)  # 1 MiB
    key = os.urandom(32)
    nonce = os.urandom(12)

    print(f"{'Cipher':<20} | {'Throughput (MiB/s)':<20}")
    print("-" * 45)

    for cipher_name, cipher in [
        ("AES-256-GCM", AesGcmCipher()),
        ("ChaCha20-Poly1305", ChaCha20Cipher()),
    ]:
        start = time.perf_counter()
        iterations = 100
        for _ in range(iterations):
            cipher.encrypt(data, key, nonce)
        end = time.perf_counter()

        duration = end - start
        throughput = (iterations * 1) / duration  # MiB/s
        print(f"{cipher_name:<20} | {throughput:>20.2f}")


if __name__ == "__main__":
    import os

    benchmark_encryption()
