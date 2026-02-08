"""
Crypto Benchmarks
Role: Benchmark individual crypto operations

Measures:
- Kyber: KeyGen, Encap, Decap
- Dilithium: KeyGen, Sign, Verify
- ChaCha20-Poly1305: Encrypt, Decrypt

Output: JSON file with timing data
Uses: pytest-benchmark for accurate measurements
"""

import os
import sys
import json
import time
from typing import Dict, Any

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from crypto.kyber_kem import KyberKEM
from crypto.dilithium_sig import DilithiumSignature
from crypto.aead import AEADCipher


def benchmark_operation(operation_name: str, operation_func, iterations: int = 100) -> Dict[str, Any]:
    """
    Benchmark a single operation.
    
    Args:
        operation_name: Name of the operation
        operation_func: Function to benchmark
        iterations: Number of iterations to run
    
    Returns:
        Dict with timing statistics
    """
    print(f"   Benchmarking {operation_name}... ", end="", flush=True)
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation_func()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to milliseconds
    
    # Calculate statistics
    times.sort()
    avg = sum(times) / len(times)
    min_time = times[0]
    max_time = times[-1]
    median = times[len(times) // 2]
    
    # Calculate percentiles
    p95_idx = int(len(times) * 0.95)
    p99_idx = int(len(times) * 0.99)
    p95 = times[p95_idx]
    p99 = times[p99_idx]
    
    print(f"[OK] (avg: {avg:.3f}ms)")
    
    return {
        "operation": operation_name,
        "iterations": iterations,
        "avg_ms": round(avg, 3),
        "min_ms": round(min_time, 3),
        "max_ms": round(max_time, 3),
        "median_ms": round(median, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
    }


def benchmark_kyber(iterations: int = 100) -> Dict[str, Any]:
    """Benchmark Kyber768 KEM operations"""
    print("\n1. Kyber768 KEM Benchmarks")
    print("   " + "-" * 40)
    
    kem = KyberKEM()
    
    # Benchmark KeyGen
    keygen_result = benchmark_operation(
        "Kyber KeyGen",
        lambda: kem.generate_keypair(),
        iterations
    )
    
    # Pre-generate keys for encap/decap benchmarks
    pk, sk = kem.generate_keypair()
    
    # Benchmark Encapsulate
    encap_result = benchmark_operation(
        "Kyber Encap",
        lambda: kem.encapsulate(pk),
        iterations
    )
    
    # Pre-generate ciphertext for decap benchmark
    ct, ss = kem.encapsulate(pk)
    
    # Benchmark Decapsulate
    decap_result = benchmark_operation(
        "Kyber Decap",
        lambda: kem.decapsulate(sk, ct),
        iterations
    )
    
    return {
        "algorithm": "Kyber768",
        "operations": {
            "keygen": keygen_result,
            "encapsulate": encap_result,
            "decapsulate": decap_result,
        }
    }


def benchmark_dilithium(iterations: int = 100) -> Dict[str, Any]:
    """Benchmark ML-DSA-65 (Dilithium3) signature operations"""
    print("\n2. ML-DSA-65 (Dilithium3) Signature Benchmarks")
    print("   " + "-" * 40)
    
    sig = DilithiumSignature()
    
    # Benchmark KeyGen
    keygen_result = benchmark_operation(
        "Dilithium KeyGen",
        lambda: sig.generate_keypair(),
        iterations
    )
    
    # Pre-generate keys for sign/verify benchmarks
    pk, sk = sig.generate_keypair()
    message = b"Benchmark message for Dilithium signature testing"
    
    # Benchmark Sign
    sign_result = benchmark_operation(
        "Dilithium Sign",
        lambda: sig.sign(sk, message),
        iterations
    )
    
    # Pre-generate signature for verify benchmark
    signature = sig.sign(sk, message)
    
    # Benchmark Verify
    verify_result = benchmark_operation(
        "Dilithium Verify",
        lambda: sig.verify(pk, message, signature),
        iterations
    )
    
    return {
        "algorithm": "ML-DSA-65 (Dilithium3)",
        "operations": {
            "keygen": keygen_result,
            "sign": sign_result,
            "verify": verify_result,
        }
    }


def benchmark_aead(iterations: int = 1000) -> Dict[str, Any]:
    """Benchmark ChaCha20-Poly1305 AEAD operations"""
    print("\n3. ChaCha20-Poly1305 AEAD Benchmarks")
    print("   " + "-" * 40)
    
    # Generate key
    key = AEADCipher.generate_key()
    cipher = AEADCipher(key)
    
    # Test data
    plaintext = b"Benchmark plaintext for AEAD encryption testing" * 10  # ~500 bytes
    aad = b"Additional authenticated data"
    
    # Benchmark Encrypt
    encrypt_result = benchmark_operation(
        "ChaCha20-Poly1305 Encrypt",
        lambda: cipher.encrypt(plaintext, aad),
        iterations
    )
    
    # Pre-generate ciphertext for decrypt benchmark
    ciphertext = cipher.encrypt(plaintext, aad)
    
    # Benchmark Decrypt
    decrypt_result = benchmark_operation(
        "ChaCha20-Poly1305 Decrypt",
        lambda: cipher.decrypt(ciphertext, aad),
        iterations
    )
    
    return {
        "algorithm": "ChaCha20-Poly1305",
        "data_size_bytes": len(plaintext),
        "operations": {
            "encrypt": encrypt_result,
            "decrypt": decrypt_result,
        }
    }


def save_results_json(results: Dict[str, Any], output_file: str):
    """Save benchmark results to JSON file"""
    print(f"\nSaving results to {output_file}...")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[OK] Results saved to {output_file}")


def print_summary(results: Dict[str, Any]):
    """Print benchmark summary"""
    print("\n" + "=" * 60)
    print("Benchmark Summary")
    print("=" * 60)
    
    for category in ["kyber", "dilithium", "aead"]:
        if category in results:
            data = results[category]
            print(f"\n{data['algorithm']}:")
            for op_name, op_data in data["operations"].items():
                print(f"  • {op_data['operation']:<25} {op_data['avg_ms']:>8.3f} ms")


def main():
    """Main benchmark workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Crypto Benchmarks")
    parser.add_argument("--iterations", type=int, default=100,
                       help="Number of iterations for Kyber/Dilithium (default: 100)")
    parser.add_argument("--aead-iterations", type=int, default=1000,
                       help="Number of iterations for AEAD (default: 1000)")
    parser.add_argument("--output", default="results_benchmarks/crypto_benchmark_results.json",
                       help="Output JSON file (default: results_benchmarks/crypto_benchmark_results.json)")
    parser.add_argument("--skip-kyber", action="store_true",
                       help="Skip Kyber benchmarks")
    parser.add_argument("--skip-dilithium", action="store_true",
                       help="Skip Dilithium benchmarks")
    parser.add_argument("--skip-aead", action="store_true",
                       help="Skip AEAD benchmarks")
    args = parser.parse_args()
    
    print("=" * 60)
    print("Post-Quantum Cryptography Benchmarks")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  • Iterations (KEM/Sig): {args.iterations}")
    print(f"  • Iterations (AEAD):    {args.aead_iterations}")
    print(f"  • Output file:          {args.output}")
    
    results = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "iterations_kem_sig": args.iterations,
            "iterations_aead": args.aead_iterations,
        }
    }
    
    try:
        # Run benchmarks
        if not args.skip_kyber:
            results["kyber"] = benchmark_kyber(args.iterations)
        
        if not args.skip_dilithium:
            results["dilithium"] = benchmark_dilithium(args.iterations)
        
        if not args.skip_aead:
            results["aead"] = benchmark_aead(args.aead_iterations)
        
        # Save results
        output_path = os.path.join(ROOT_DIR, args.output)
        # Create results directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"\n[OK] Created directory: {output_dir}")
        save_results_json(results, output_path)
        
        # Print summary
        print_summary(results)
        
        print("\n" + "=" * 60)
        print("✅ Benchmarks Complete")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[FAIL] Benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Benchmark stopped")
        sys.exit(0)
