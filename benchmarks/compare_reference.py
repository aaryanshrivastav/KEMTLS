"""
Compare with Reference Implementation
Role: Compare with reference implementation

Compares: Your results vs. Schardong et al. (2023)
Generates: Comparison tables, improvement percentages
Output: Visualization graphs (matplotlib)
"""

import os
import sys
import json
from typing import Dict, Any, List
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

# Reference data from Schardong et al. (2023)
# "Post-Quantum OIDC: A Quantum-Resistant Authentication Approach"
REFERENCE_DATA = {
    "paper": "Schardong et al. (2023)",
    "title": "Post-Quantum OIDC: A Quantum-Resistant Authentication Approach",
    "implementation": "Reference Implementation",
    
    # Crypto operations (milliseconds)
    "crypto": {
        "kyber_keygen": 0.45,
        "kyber_encap": 0.52,
        "kyber_decap": 0.48,
        "dilithium_keygen": 1.20,
        "dilithium_sign": 2.80,
        "dilithium_verify": 1.50,
        "chacha20_encrypt": 0.08,
        "chacha20_decrypt": 0.08,
    },
    
    # Protocol operations (milliseconds)
    "protocol": {
        "kemtls_handshake": 8.50,
        "jwt_create": 3.00,
        "jwt_verify": 1.60,
        "pop_generate": 2.90,
        "pop_verify": 3.20,
    },
    
    # End-to-end flow (milliseconds)
    "end_to_end": {
        "total": 18.50,
        "phase1_kemtls": 8.50,
        "phase2_authorization": 0.50,
        "phase3_token": 3.00,
        "phase4_resource": 6.50,
    }
}


def load_benchmark_results(results_dir: str) -> Dict[str, Any]:
    """Load benchmark results from JSON files"""
    results = {}
    
    # Load crypto benchmarks
    crypto_path = os.path.join(results_dir, "crypto_benchmark_results.json")
    if os.path.exists(crypto_path):
        with open(crypto_path, "r") as f:
            results["crypto"] = json.load(f)
        print(f"✓ Loaded crypto benchmarks: {crypto_path}")
    
    # Load protocol benchmarks
    protocol_path = os.path.join(results_dir, "protocol_benchmark_results.json")
    if os.path.exists(protocol_path):
        with open(protocol_path, "r") as f:
            results["protocol"] = json.load(f)
        print(f"✓ Loaded protocol benchmarks: {protocol_path}")
    
    # Load end-to-end benchmarks
    e2e_path = os.path.join(results_dir, "end_to_end_benchmark_results.json")
    if os.path.exists(e2e_path):
        with open(e2e_path, "r") as f:
            results["end_to_end"] = json.load(f)
        print(f"✓ Loaded end-to-end benchmarks: {e2e_path}")
    
    return results


def extract_our_results(benchmark_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract our timing data in comparable format"""
    our_data = {}
    
    # Extract crypto results
    if "crypto" in benchmark_data:
        crypto = benchmark_data["crypto"]
        our_data["crypto"] = {
            "kyber_keygen": crypto.get("kyber", {}).get("operations", {}).get("keygen", {}).get("avg_ms", 0),
            "kyber_encap": crypto.get("kyber", {}).get("operations", {}).get("encapsulate", {}).get("avg_ms", 0),
            "kyber_decap": crypto.get("kyber", {}).get("operations", {}).get("decapsulate", {}).get("avg_ms", 0),
            "dilithium_keygen": crypto.get("dilithium", {}).get("operations", {}).get("keygen", {}).get("avg_ms", 0),
            "dilithium_sign": crypto.get("dilithium", {}).get("operations", {}).get("sign", {}).get("avg_ms", 0),
            "dilithium_verify": crypto.get("dilithium", {}).get("operations", {}).get("verify", {}).get("avg_ms", 0),
            "chacha20_encrypt": crypto.get("aead", {}).get("operations", {}).get("encrypt", {}).get("avg_ms", 0),
            "chacha20_decrypt": crypto.get("aead", {}).get("operations", {}).get("decrypt", {}).get("avg_ms", 0),
        }
    
    # Extract protocol results
    if "protocol" in benchmark_data:
        protocol = benchmark_data["protocol"]
        our_data["protocol"] = {
            "kemtls_handshake": protocol.get("kemtls", {}).get("operations", {}).get("full_handshake", {}).get("avg_ms", 0),
            "jwt_create": protocol.get("jwt", {}).get("operations", {}).get("create_token", {}).get("avg_ms", 0),
            "jwt_verify": protocol.get("jwt", {}).get("operations", {}).get("verify_token", {}).get("avg_ms", 0),
            "pop_generate": protocol.get("pop", {}).get("operations", {}).get("generate_proof", {}).get("avg_ms", 0),
            "pop_verify": protocol.get("pop", {}).get("operations", {}).get("verify_proof", {}).get("avg_ms", 0),
        }
    
    # Extract end-to-end results
    if "end_to_end" in benchmark_data:
        e2e = benchmark_data["end_to_end"]
        stats = e2e.get("statistics", {})
        our_data["end_to_end"] = {
            "total": stats.get("total", {}).get("avg_ms", 0),
            "phase1_kemtls": stats.get("phase1", {}).get("avg_ms", 0),
            "phase2_authorization": stats.get("phase2", {}).get("avg_ms", 0),
            "phase3_token": stats.get("phase3", {}).get("avg_ms", 0),
            "phase4_resource": stats.get("phase4", {}).get("avg_ms", 0),
        }
    
    return our_data


def calculate_comparison(reference: float, ours: float) -> Dict[str, Any]:
    """Calculate comparison metrics"""
    if reference == 0:
        return {"diff": 0, "ratio": 1.0, "improvement": 0}
    
    diff = ours - reference
    ratio = ours / reference
    improvement = ((reference - ours) / reference) * 100  # Positive = we're faster
    
    return {
        "diff": round(diff, 3),
        "ratio": round(ratio, 3),
        "improvement": round(improvement, 2)
    }


def generate_comparison_table(category: str, reference_data: Dict, our_data: Dict):
    """Generate comparison table for a category"""
    print(f"\n{'=' * 80}")
    print(f"{category.upper()} COMPARISON")
    print('=' * 80)
    print(f"{'Operation':<25} {'Reference':<12} {'Our Impl':<12} {'Diff':<10} {'Ratio':<8} {'Improvement':<12}")
    print('-' * 80)
    
    for operation, ref_value in reference_data.items():
        our_value = our_data.get(operation, 0)
        comp = calculate_comparison(ref_value, our_value)
        
        # Format improvement with color indicator
        improvement_str = f"{comp['improvement']:+.1f}%"
        if comp['improvement'] > 0:
            improvement_str += " ✓"
        elif comp['improvement'] < -10:
            improvement_str += " ⚠"
        
        print(f"{operation:<25} {ref_value:>10.2f}ms {our_value:>10.2f}ms {comp['diff']:>8.2f}ms {comp['ratio']:>6.2f}x {improvement_str:<12}")


def plot_crypto_comparison(reference_data: Dict, our_data: Dict, output_file: str):
    """Generate crypto operations comparison bar chart"""
    operations = list(reference_data.keys())
    ref_values = [reference_data[op] for op in operations]
    our_values = [our_data.get(op, 0) for op in operations]
    
    # Clean up operation names for display
    display_names = [op.replace("_", " ").title() for op in operations]
    
    fig, ax = plt.subplots(figsize=(12, 6))
    x = range(len(operations))
    width = 0.35
    
    bars1 = ax.bar([i - width/2 for i in x], ref_values, width, label='Reference (Schardong et al. 2023)', color='#3498db')
    bars2 = ax.bar([i + width/2 for i in x], our_values, width, label='Our Implementation', color='#2ecc71')
    
    ax.set_xlabel('Cryptographic Operations', fontsize=12, fontweight='bold')
    ax.set_ylabel('Time (milliseconds)', fontsize=12, fontweight='bold')
    ax.set_title('Cryptographic Operations Performance Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"✓ Saved crypto comparison chart: {output_file}")
    plt.close()


def plot_protocol_comparison(reference_data: Dict, our_data: Dict, output_file: str):
    """Generate protocol operations comparison bar chart"""
    operations = list(reference_data.keys())
    ref_values = [reference_data[op] for op in operations]
    our_values = [our_data.get(op, 0) for op in operations]
    
    display_names = [op.replace("_", " ").title() for op in operations]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    x = range(len(operations))
    width = 0.35
    
    bars1 = ax.bar([i - width/2 for i in x], ref_values, width, label='Reference', color='#e74c3c')
    bars2 = ax.bar([i + width/2 for i in x], our_values, width, label='Our Implementation', color='#9b59b6')
    
    ax.set_xlabel('Protocol Operations', fontsize=12, fontweight='bold')
    ax.set_ylabel('Time (milliseconds)', fontsize=12, fontweight='bold')
    ax.set_title('Protocol-Level Performance Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"✓ Saved protocol comparison chart: {output_file}")
    plt.close()


def plot_end_to_end_comparison(reference_data: Dict, our_data: Dict, output_file: str):
    """Generate end-to-end flow comparison stacked bar chart"""
    phases = ["phase1_kemtls", "phase2_authorization", "phase3_token", "phase4_resource"]
    phase_names = ["KEMTLS\nHandshake", "Authorization", "Token\nExchange", "Resource\nAccess"]
    
    ref_values = [reference_data.get(p, 0) for p in phases]
    our_values = [our_data.get(p, 0) for p in phases]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    x = [0, 1]
    width = 0.5
    
    # Stacked bars
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
    
    bottom_ref = 0
    bottom_our = 0
    for i, (phase, name) in enumerate(zip(phases, phase_names)):
        ax.bar(0, ref_values[i], width, bottom=bottom_ref, label=name if i < len(phases) else "", color=colors[i])
        ax.bar(1, our_values[i], width, bottom=bottom_our, color=colors[i])
        bottom_ref += ref_values[i]
        bottom_our += our_values[i]
    
    ax.set_ylabel('Time (milliseconds)', fontsize=12, fontweight='bold')
    ax.set_title('End-to-End Authentication Flow Comparison', fontsize=14, fontweight='bold')
    ax.set_xticks([0, 1])
    ax.set_xticklabels(['Reference\n(Schardong et al.)', 'Our Implementation'])
    ax.legend(loc='upper left', bbox_to_anchor=(1, 1))
    ax.grid(axis='y', alpha=0.3)
    
    # Add total time annotations
    ax.text(0, bottom_ref + 0.5, f'{bottom_ref:.1f}ms', ha='center', fontweight='bold')
    ax.text(1, bottom_our + 0.5, f'{bottom_our:.1f}ms', ha='center', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    print(f"✓ Saved end-to-end comparison chart: {output_file}")
    plt.close()


def generate_summary_report(reference: Dict, our_results: Dict, output_file: str):
    """Generate comprehensive summary report"""
    with open(output_file, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("PERFORMANCE COMPARISON SUMMARY REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Reference: {REFERENCE_DATA['paper']}\n")
        f.write(f"Title: {REFERENCE_DATA['title']}\n\n")
        
        # Overall summary
        if "end_to_end" in reference and "end_to_end" in our_results:
            ref_total = reference["end_to_end"]["total"]
            our_total = our_results["end_to_end"]["total"]
            comp = calculate_comparison(ref_total, our_total)
            
            f.write("OVERALL PERFORMANCE\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Authentication Time (Reference): {ref_total:.2f}ms\n")
            f.write(f"Total Authentication Time (Ours):      {our_total:.2f}ms\n")
            f.write(f"Difference:                             {comp['diff']:+.2f}ms\n")
            f.write(f"Performance Ratio:                      {comp['ratio']:.2f}x\n")
            f.write(f"Improvement:                            {comp['improvement']:+.1f}%\n\n")
        
        # Detailed breakdowns
        for category in ["crypto", "protocol", "end_to_end"]:
            if category in reference and category in our_results:
                f.write(f"\n{category.upper()} OPERATIONS\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'Operation':<30} {'Reference':<12} {'Ours':<12} {'Improvement':<15}\n")
                f.write("-" * 80 + "\n")
                
                for op, ref_val in reference[category].items():
                    our_val = our_results[category].get(op, 0)
                    comp = calculate_comparison(ref_val, our_val)
                    f.write(f"{op:<30} {ref_val:>10.2f}ms {our_val:>10.2f}ms {comp['improvement']:>12.1f}%\n")
                f.write("\n")
    
    print(f"✓ Saved summary report: {output_file}")


def main():
    """Main comparison workflow"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Compare with Reference Implementation")
    parser.add_argument("--results-dir", default="results_benchmarks",
                       help="Directory with benchmark results (default: results_benchmarks)")
    parser.add_argument("--output-dir", default="results_benchmarks/comparison",
                       help="Output directory for charts (default: results_benchmarks/comparison)")
    args = parser.parse_args()
    
    print("=" * 80)
    print("Performance Comparison with Reference Implementation")
    print("=" * 80)
    print(f"\nReference: {REFERENCE_DATA['paper']}")
    print(f"Paper: {REFERENCE_DATA['title']}\n")
    
    # Load our benchmark results
    results_dir = os.path.join(ROOT_DIR, args.results_dir)
    print(f"Loading benchmark results from: {results_dir}")
    
    if not os.path.exists(results_dir):
        print(f"\n❌ Results directory not found: {results_dir}")
        print("   Run benchmarks first:")
        print("   python benchmarks/crypto_benchmarks.py")
        print("   python benchmarks/protocol_benchmarks.py")
        print("   python benchmarks/end_to_end_benchmark.py")
        sys.exit(1)
    
    benchmark_data = load_benchmark_results(results_dir)
    
    if not benchmark_data:
        print("\n❌ No benchmark results found!")
        print("   Run benchmarks first before comparison.")
        sys.exit(1)
    
    # Extract our results in comparable format
    our_results = extract_our_results(benchmark_data)
    
    # Generate comparison tables
    if "crypto" in REFERENCE_DATA and "crypto" in our_results:
        generate_comparison_table("Crypto Operations", REFERENCE_DATA["crypto"], our_results["crypto"])
    
    if "protocol" in REFERENCE_DATA and "protocol" in our_results:
        generate_comparison_table("Protocol Operations", REFERENCE_DATA["protocol"], our_results["protocol"])
    
    if "end_to_end" in REFERENCE_DATA and "end_to_end" in our_results:
        generate_comparison_table("End-to-End Flow", REFERENCE_DATA["end_to_end"], our_results["end_to_end"])
    
    # Create output directory
    output_dir = os.path.join(ROOT_DIR, args.output_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"\n✓ Created output directory: {output_dir}")
    
    # Generate visualizations
    print("\nGenerating comparison charts...")
    
    if "crypto" in our_results:
        plot_crypto_comparison(
            REFERENCE_DATA["crypto"],
            our_results["crypto"],
            os.path.join(output_dir, "crypto_comparison.png")
        )
    
    if "protocol" in our_results:
        plot_protocol_comparison(
            REFERENCE_DATA["protocol"],
            our_results["protocol"],
            os.path.join(output_dir, "protocol_comparison.png")
        )
    
    if "end_to_end" in our_results:
        plot_end_to_end_comparison(
            REFERENCE_DATA["end_to_end"],
            our_results["end_to_end"],
            os.path.join(output_dir, "end_to_end_comparison.png")
        )
    
    # Generate summary report
    report_path = os.path.join(output_dir, "comparison_report.txt")
    generate_summary_report(REFERENCE_DATA, our_results, report_path)
    
    print("\n" + "=" * 80)
    print("✅ Comparison Complete")
    print("=" * 80)
    print(f"\nOutput saved to: {output_dir}")
    print("  • crypto_comparison.png")
    print("  • protocol_comparison.png")
    print("  • end_to_end_comparison.png")
    print("  • comparison_report.txt")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Comparison stopped")
        sys.exit(0)
