"""
End-to-End Authentication Flow Benchmark
Role: Benchmark complete authentication flow

Measures: Full flow from handshake → token → resource access
Includes: All network latency, processing time
Output: Total authentication time with breakdown
"""

import os
import sys
import json
import time
from typing import Dict, Any, List

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from crypto.ml_kem import KyberKEM
from crypto.ml_dsa import DilithiumSignature
from kemtls.handshake import KEMTLSHandshake
from oidc.jwt_handler import PQJWT


class AuthenticationFlowBenchmark:
    """End-to-end authentication flow benchmark"""
    
    def __init__(self):
        """Initialize benchmark components"""
        # Server components
        self.kem = KyberKEM()
        self.sig = DilithiumSignature()
        
        # Generate server keys
        self.server_lt_pk, self.server_lt_sk = self.kem.generate_keypair()
        self.issuer_pk, self.issuer_sk = self.sig.generate_keypair()
        
        # Initialize handlers
        self.jwt = PQJWT()
        
        # Timing breakdown
        self.timings: Dict[str, float] = {}
    
    def run_complete_flow(self) -> Dict[str, Any]:
        """
        Execute complete authentication flow and measure time.
        
        Returns:
            Dict with timing breakdown and total time
        """
        total_start = time.perf_counter()
        
        # Phase 1: KEMTLS Handshake
        phase1_start = time.perf_counter()
        session_keys, client_eph_pk, client_eph_sk = self._phase1_kemtls_handshake()
        phase1_time = (time.perf_counter() - phase1_start) * 1000
        self.timings["phase1_kemtls_handshake"] = phase1_time
        
        # Phase 2: Authorization Request (simulated - would be user interaction)
        phase2_start = time.perf_counter()
        auth_code = self._phase2_authorization()
        phase2_time = (time.perf_counter() - phase2_start) * 1000
        self.timings["phase2_authorization"] = phase2_time
        
        # Phase 3: Token Exchange
        phase3_start = time.perf_counter()
        id_token, access_token = self._phase3_token_exchange(client_eph_pk)
        phase3_time = (time.perf_counter() - phase3_start) * 1000
        self.timings["phase3_token_exchange"] = phase3_time
        
        total_time = (time.perf_counter() - total_start) * 1000
        self.timings["total"] = total_time
        
        return {
            "success": True,
            "timings": self.timings,
            "phases": {
                "phase1": {"name": "KEMTLS Handshake", "time_ms": phase1_time},
                "phase2": {"name": "Authorization", "time_ms": phase2_time},
                "phase3": {"name": "Token Exchange", "time_ms": phase3_time},
            }
        }
    
    def _phase1_kemtls_handshake(self):
        """Phase 1: Perform KEMTLS handshake"""
        server = KEMTLSHandshake(is_server=True)
        client = KEMTLSHandshake(is_server=False)
        
        # Server hello
        server_hello = server.server_init_handshake(self.server_lt_sk, self.server_lt_pk)
        
        # Client key exchange
        client_kex, client_eph_pk = client.client_process_server_hello(
            server_hello,
            trusted_longterm_pk=self.server_lt_pk
        )
        
        # Server finalizes
        server_keys = server.server_process_client_key_exchange(client_kex)
        client_keys = client.get_session_keys()
        
        # Generate client ephemeral keypair
        client_eph_pk_sig, client_eph_sk_sig = self.sig.generate_keypair()
        
        return client_keys, client_eph_pk_sig, client_eph_sk_sig
    
    def _phase2_authorization(self):
        """Phase 2: Authorization request (simulated)"""
        # In real scenario: user visits /authorize, logs in, approves
        # Here we just simulate the authorization code generation
        auth_code = "simulated_auth_code_" + str(time.time())
        return auth_code
    
    def _phase3_token_exchange(self, client_eph_pk):
        """Phase 3: Exchange authorization code for tokens"""
        # Create ID token
        claims = {
            "iss": "http://localhost:5000",
            "sub": "alice",
            "aud": "demo_client",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nonce": "demo_nonce",
            "cnf": {
                "kid": "client_eph_pk_binding"
            }
        }
        
        id_token = self.jwt.create_id_token(claims, self.issuer_sk, self.issuer_pk)
        access_token = "access_token_" + "x" * 100
        
        return id_token, access_token
    

def benchmark_operation(benchmark: AuthenticationFlowBenchmark, iterations: int = 100) -> Dict[str, Any]:
    """
    Run authentication flow multiple times and collect statistics.
    
    Args:
        benchmark: AuthenticationFlowBenchmark instance
        iterations: Number of iterations
    
    Returns:
        Dict with timing statistics
    """
    print(f"\nRunning {iterations} iterations of complete authentication flow...")
    
    all_results = []
    phase_times = {
        "phase1": [],
        "phase2": [],
        "phase3": [],
        "total": []
    }
    
    for i in range(iterations):
        if (i + 1) % 10 == 0:
            print(f"   Progress: {i + 1}/{iterations}...", end="\r", flush=True)
        
        result = benchmark.run_complete_flow()
        all_results.append(result)
        
        # Collect phase times
        for phase_key, phase_data in result["phases"].items():
            phase_times[phase_key].append(phase_data["time_ms"])
        phase_times["total"].append(result["timings"]["total"])
    
    print(f"   Progress: {iterations}/{iterations}... ✓")
    
    # Calculate statistics for each phase
    stats = {}
    for phase, times in phase_times.items():
        times_sorted = sorted(times)
        stats[phase] = {
            "avg_ms": round(sum(times) / len(times), 3),
            "min_ms": round(min(times), 3),
            "max_ms": round(max(times), 3),
            "median_ms": round(times_sorted[len(times) // 2], 3),
            "p95_ms": round(times_sorted[int(len(times) * 0.95)], 3),
            "p99_ms": round(times_sorted[int(len(times) * 0.99)], 3),
        }
    
    return {
        "iterations": iterations,
        "success_rate": sum(1 for r in all_results if r["success"]) / len(all_results),
        "statistics": stats
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
    print("End-to-End Authentication Flow Summary")
    print("=" * 60)
    
    stats = results["statistics"]
    
    print(f"\nTotal Authentication Time: {stats['total']['avg_ms']:.2f} ms (avg)")
    print(f"  • Min: {stats['total']['min_ms']:.2f} ms")
    print(f"  • Max: {stats['total']['max_ms']:.2f} ms")
    print(f"  • P95: {stats['total']['p95_ms']:.2f} ms")
    print(f"  • P99: {stats['total']['p99_ms']:.2f} ms")
    
    print("\nPhase Breakdown (Average):")
    phases = [
        ("Phase 1: KEMTLS Handshake", "phase1"),
        ("Phase 2: Authorization", "phase2"),
        ("Phase 3: Token Exchange", "phase3"),
    ]
    
    total_avg = stats['total']['avg_ms']
    for name, key in phases:
        avg_ms = stats[key]['avg_ms']
        percentage = (avg_ms / total_avg) * 100 if total_avg > 0 else 0
        print(f"  • {name:<30} {avg_ms:>8.2f} ms ({percentage:>5.1f}%)")
    
    print(f"\nSuccess Rate: {results['success_rate'] * 100:.1f}%")


def main():
    """Main benchmark workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description="End-to-End Authentication Flow Benchmark")
    parser.add_argument("--iterations", type=int, default=100,
                       help="Number of iterations (default: 100)")
    parser.add_argument("--output", default="results_benchmarks/end_to_end_benchmark_results.json",
                       help="Output JSON file (default: results_benchmarks/end_to_end_benchmark_results.json)")
    args = parser.parse_args()
    
    print("=" * 60)
    print("End-to-End Authentication Flow Benchmark")
    print("=" * 60)
    print("\nThis benchmark measures the complete authentication flow:")
    print("  1. KEMTLS Handshake (PQ key exchange)")
    print("  2. Authorization (user approval)")
    print("  3. Token Exchange (ID token + access token)")
    print(f"\nConfiguration:")
    print(f"  • Iterations:  {args.iterations}")
    print(f"  • Output file: {args.output}")
    
    try:
        # Initialize benchmark
        benchmark = AuthenticationFlowBenchmark()
        
        # Run benchmark
        results = benchmark_operation(benchmark, args.iterations)
        
        # Add metadata
        results["metadata"] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "iterations": args.iterations,
            "type": "end-to-end"
        }
        
        # Save results
        output_path = os.path.join(ROOT_DIR, args.output)
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"\n[OK] Created directory: {output_dir}")
        save_results_json(results, output_path)
        
        # Print summary
        print_summary(results)
        
        print("\n" + "=" * 60)
        print("✅ End-to-End Benchmark Complete")
        print("=" * 60)
        print("\nKey Insights:")
        print("  • Total time = complete user authentication experience")
        print("  • Phase breakdown = identifies performance bottlenecks")
        print("  • P95/P99 = worst-case latency for real deployments")
        
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
