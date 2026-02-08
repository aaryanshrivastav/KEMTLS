"""
Run All Benchmarks
Role: Execute all benchmarks

Workflow:
1. Run crypto benchmarks
2. Run protocol benchmarks
3. Run end-to-end benchmarks
4. Generate comparison with reference
5. Save results to JSON
6. Generate graphs
"""

import sys
import os
import subprocess
import time
import argparse
# Force UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
BENCHMARKS_DIR = os.path.join(ROOT_DIR, "benchmarks")


def print_section(title):
    """Print section header"""
    print("\n" + "=" * 80)
    print(f"{title}")
    print("=" * 80)


def run_command(cmd, description):
    """
    Run a command and capture its output.
    
    Args:
        cmd: Command to run (list)
        description: Description of what's running
    
    Returns:
        bool: True if successful, False otherwise
    """
    print(f"\n> {description}...")
    print(f"   Command: {' '.join(cmd)}")
    
    start = time.time()
    try:

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"

        result = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            check=True,
            capture_output=True,
            text=True,
            env=env
        )

        elapsed = time.time() - start
        print(f"   [OK] Completed in {elapsed:.2f}s")
        return True
    except subprocess.CalledProcessError as e:
        elapsed = time.time() - start
        print(f"   [FAIL] Failed after {elapsed:.2f}s")
        print(f"   Error: {e.stderr}")
        return False


def main():
    """Main benchmark orchestration workflow"""
    parser = argparse.ArgumentParser(description="Run All Benchmarks")
    parser.add_argument("--iterations", type=int, default=100,
                       help="Number of iterations for benchmarks (default: 100)")
    parser.add_argument("--skip-crypto", action="store_true",
                       help="Skip crypto benchmarks")
    parser.add_argument("--skip-protocol", action="store_true",
                       help="Skip protocol benchmarks")
    parser.add_argument("--skip-e2e", action="store_true",
                       help="Skip end-to-end benchmarks")
    parser.add_argument("--skip-comparison", action="store_true",
                       help="Skip comparison with reference")
    parser.add_argument("--output-dir", default="results_benchmarks",
                       help="Output directory for results (default: results_benchmarks)")
    args = parser.parse_args()
    
    print_section("POST-QUANTUM OIDC + KEMTLS BENCHMARK SUITE")
    print(f"\nConfiguration:")
    print(f"  • Iterations:     {args.iterations}")
    print(f"  • Output Dir:     {args.output_dir}")
    print(f"  • Skip Crypto:    {args.skip_crypto}")
    print(f"  • Skip Protocol:  {args.skip_protocol}")
    print(f"  • Skip E2E:       {args.skip_e2e}")
    print(f"  • Skip Compare:   {args.skip_comparison}")
    
    # Create output directory
    output_dir = os.path.join(ROOT_DIR, args.output_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"\n✓ Created output directory: {output_dir}")
    
    start_time = time.time()
    results = {
        "crypto": False,
        "protocol": False,
        "e2e": False,
        "comparison": False
    }
    
    # Phase 1: Crypto Benchmarks
    if not args.skip_crypto:
        print_section("PHASE 1: Crypto Benchmarks")
        results["crypto"] = run_command(
            [sys.executable, os.path.join(BENCHMARKS_DIR, "crypto_benchmarks.py"),
             "--iterations", str(args.iterations),
             "--output", f"{args.output_dir}/crypto_benchmark_results.json"],
            "Running crypto benchmarks (Kyber, Dilithium, ChaCha20)"
        )
    else:
        print_section("PHASE 1: Crypto Benchmarks [SKIPPED]")
    
    # Phase 2: Protocol Benchmarks
    if not args.skip_protocol:
        print_section("PHASE 2: Protocol Benchmarks")
        results["protocol"] = run_command(
            [sys.executable, os.path.join(BENCHMARKS_DIR, "protocol_benchmarks.py"),
             "--iterations", str(args.iterations),
             "--output", f"{args.output_dir}/protocol_benchmark_results.json"],
            "Running protocol benchmarks (KEMTLS, JWT, PoP)"
        )
    else:
        print_section("PHASE 2: Protocol Benchmarks [SKIPPED]")
    
    # Phase 3: End-to-End Benchmarks
    if not args.skip_e2e:
        print_section("PHASE 3: End-to-End Benchmarks")
        results["e2e"] = run_command(
            [sys.executable, os.path.join(BENCHMARKS_DIR, "end_to_end_benchmark.py"),
             "--iterations", str(args.iterations),
             "--output", f"{args.output_dir}/end_to_end_benchmark_results.json"],
            "Running end-to-end authentication flow benchmarks"
        )
    else:
        print_section("PHASE 3: End-to-End Benchmarks [SKIPPED]")
    
    # Phase 4: Comparison with Reference
    if not args.skip_comparison:
        print_section("PHASE 4: Comparison with Reference Implementation")
        results["comparison"] = run_command(
            [sys.executable, os.path.join(BENCHMARKS_DIR, "compare_reference.py"),
             "--results-dir", args.output_dir,
             "--output-dir", f"{args.output_dir}/comparison"],
            "Generating comparison with Schardong et al. (2023)"
        )
    else:
        print_section("PHASE 4: Comparison [SKIPPED]")
    
    # Summary
    total_time = time.time() - start_time
    print_section("BENCHMARK SUITE SUMMARY")
    
    print(f"\nExecution Time: {total_time:.2f}s ({total_time/60:.1f} minutes)")
    
    print("\nResults:")
    status_text = lambda x: "[PASS]" if x else "[FAIL]"
    print(f"  • Crypto Benchmarks:     {status_text(results['crypto'])}")
    print(f"  • Protocol Benchmarks:   {status_text(results['protocol'])}")
    print(f"  • End-to-End Benchmarks: {status_text(results['e2e'])}")
    print(f"  • Comparison Report:     {status_text(results['comparison'])}")
    
    success_count = sum(1 for v in results.values() if v)
    total_count = sum(1 for k, v in results.items() if not getattr(args, f"skip_{k.replace('e2e', 'e2e').replace('comparison', 'comparison')}", False))
    
    print(f"\nOverall: {success_count}/{total_count} phases successful")
    
    print(f"\nOutput Directory: {output_dir}")
    print("  Files:")
    print("  • crypto_benchmark_results.json")
    print("  • protocol_benchmark_results.json")
    print("  • end_to_end_benchmark_results.json")
    print("  • comparison/crypto_comparison.png")
    print("  • comparison/protocol_comparison.png")
    print("  • comparison/end_to_end_comparison.png")
    print("  • comparison/comparison_report.txt")
    
    if all(results.values()):
        print("\n" + "=" * 80)
        print("SUCCESS: ALL BENCHMARKS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        return 0
    else:
        print("\n" + "=" * 80)
        print("WARNING: SOME BENCHMARKS FAILED")
        print("=" * 80)
        print("\nCheck the error messages above for details.")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nBenchmark suite interrupted")
        sys.exit(1)
