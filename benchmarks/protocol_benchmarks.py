"""
Protocol Benchmarks
Role: Benchmark protocol-level operations

Measures:
- KEMTLS full handshake
- ID token creation
- ID token verification
- PoP proof generation
- PoP proof verification

Output: JSON file with protocol timings
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
from kemtls.handshake import KEMTLSHandshake
from oidc.jwt_handler import PQJWT
from pop.client import PoPClient
from pop.server import ProofOfPossession


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


def benchmark_kemtls_handshake(iterations: int = 100) -> Dict[str, Any]:
    """Benchmark full KEMTLS handshake"""
    print("\n1. KEMTLS Handshake Benchmarks")
    print("   " + "-" * 40)
    
    # Pre-generate server long-term keypair
    kem = KyberKEM()
    server_lt_pk, server_lt_sk = kem.generate_keypair()
    
    def full_handshake():
        """Execute complete KEMTLS handshake"""
        server = KEMTLSHandshake(is_server=True)
        client = KEMTLSHandshake(is_server=False)
        
        # Server hello
        server_hello = server.server_init_handshake(server_lt_sk, server_lt_pk)
        
        # Client key exchange
        client_kex, _ = client.client_process_server_hello(
            server_hello,
            trusted_longterm_pk=server_lt_pk
        )
        
        # Server finalizes
        server_keys = server.server_process_client_key_exchange(client_kex)
        client_keys = client.get_session_keys()
        
        return server_keys, client_keys
    
    handshake_result = benchmark_operation(
        "KEMTLS Full Handshake",
        full_handshake,
        iterations
    )
    
    return {
        "protocol": "KEMTLS",
        "description": "Full handshake including key exchange and key derivation",
        "operations": {
            "full_handshake": handshake_result,
        }
    }


def benchmark_jwt_operations(iterations: int = 100) -> Dict[str, Any]:
    """Benchmark JWT ID token operations"""
    print("\n2. JWT ID Token Benchmarks")
    print("   " + "-" * 40)
    
    jwt = PQJWT()
    sig = DilithiumSignature()
    issuer_pk, issuer_sk = sig.generate_keypair()
    
    # Sample claims
    claims = {
        "iss": "http://localhost:5000",
        "sub": "alice",
        "aud": "demo_client",
        "exp": 1999999999,
        "iat": 1000000000,
        "nonce": "test_nonce_123",
        "cnf": {
            "kid": "client_key_id"
        }
    }
    
    # Benchmark token creation
    create_result = benchmark_operation(
        "ID Token Creation",
        lambda: jwt.create_id_token(claims, issuer_sk, issuer_pk),
        iterations
    )
    
    # Pre-generate token for verification benchmark
    id_token = jwt.create_id_token(claims, issuer_sk, issuer_pk)
    
    # Benchmark token verification
    verify_result = benchmark_operation(
        "ID Token Verification",
        lambda: jwt.verify_id_token(id_token, issuer_pk),
        iterations
    )
    
    return {
        "protocol": "PQ-JWT",
        "description": "ID token creation and verification with ML-DSA-65 signatures",
        "operations": {
            "create_token": create_result,
            "verify_token": verify_result,
        }
    }


def benchmark_pop_operations(iterations: int = 100) -> Dict[str, Any]:
    """Benchmark Proof-of-Possession operations"""
    print("\n3. Proof-of-Possession (PoP) Benchmarks")
    print("   " + "-" * 40)
    
    # Setup client and server
    sig = DilithiumSignature()
    client_eph_pk, client_eph_sk = sig.generate_keypair()
    
    pop_client = PoPClient(client_eph_sk)
    pop_server = ProofOfPossession()
    
    # Pre-generate challenge and token
    challenge = pop_server.generate_challenge()
    access_token = "demo_access_token_" + "x" * 100
    
    # Benchmark PoP proof generation
    generate_result = benchmark_operation(
        "PoP Proof Generation",
        lambda: pop_client.create_pop_proof(challenge, access_token),
        iterations
    )
    
    # Pre-generate proof for verification benchmark
    proof = pop_client.create_pop_proof(challenge, access_token)
    
    # Benchmark PoP proof verification
    verify_result = benchmark_operation(
        "PoP Proof Verification",
        lambda: pop_server.verify_pop_response(challenge, proof, client_eph_pk, access_token),
        iterations
    )
    
    return {
        "protocol": "PoP",
        "description": "Proof-of-Possession for token binding",
        "operations": {
            "generate_proof": generate_result,
            "verify_proof": verify_result,
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
    print("Protocol Benchmark Summary")
    print("=" * 60)
    
    for category in ["kemtls", "jwt", "pop"]:
        if category in results:
            data = results[category]
            print(f"\n{data['protocol']} ({data['description']}):")
            for op_name, op_data in data["operations"].items():
                print(f"  • {op_data['operation']:<30} {op_data['avg_ms']:>8.3f} ms")


def main():
    """Main benchmark workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Protocol Benchmarks")
    parser.add_argument("--iterations", type=int, default=100,
                       help="Number of iterations (default: 100)")
    parser.add_argument("--output", default="results_benchmarks/protocol_benchmark_results.json",
                       help="Output JSON file (default: results_benchmarks/protocol_benchmark_results.json)")
    parser.add_argument("--skip-kemtls", action="store_true",
                       help="Skip KEMTLS benchmarks")
    parser.add_argument("--skip-jwt", action="store_true",
                       help="Skip JWT benchmarks")
    parser.add_argument("--skip-pop", action="store_true",
                       help="Skip PoP benchmarks")
    args = parser.parse_args()
    
    print("=" * 60)
    print("Protocol-Level Benchmarks")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  • Iterations:  {args.iterations}")
    print(f"  • Output file: {args.output}")
    
    results = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "iterations": args.iterations,
            "type": "protocol-level"
        }
    }
    
    try:
        # Run benchmarks
        if not args.skip_kemtls:
            results["kemtls"] = benchmark_kemtls_handshake(args.iterations)
        
        if not args.skip_jwt:
            results["jwt"] = benchmark_jwt_operations(args.iterations)
        
        if not args.skip_pop:
            results["pop"] = benchmark_pop_operations(args.iterations)
        
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
        print("✅ Protocol Benchmarks Complete")
        print("=" * 60)
        print("\nKey Insights:")
        print("  • KEMTLS handshake time = full PQ key exchange overhead")
        print("  • JWT operations = token issuance/validation cost")
        print("  • PoP operations = token binding overhead per request")
        
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
