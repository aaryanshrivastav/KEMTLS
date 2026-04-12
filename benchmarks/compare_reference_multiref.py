from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import numpy as np

# --- Constants & Paths ---
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
RESULTS_DIR = ROOT_DIR / "benchmarks" / "results"
COMPARISON_DIR = SCRIPT_DIR / "comparison"
METRICS_JSON = RESULTS_DIR / "presentation_metrics.json"

def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))

def draw_generic_table(ax, title, columns, data, highlight_col=3):
    ax.axis('off')
    ax.set_title(title, fontsize=16, weight='bold', pad=20, color='#1A56DB')
    
    table = ax.table(
        cellText=data,
        colLabels=columns,
        cellLoc='center',
        loc='center',
        colColours=["#f2f2f2"] * len(columns)
    )
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.0, 2.5)
    
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_text_props(weight='bold', color='white')
            cell.set_facecolor('#1A56DB')
        elif col == highlight_col:
            cell.set_facecolor('#F0FFF4')
            cell.get_text().set_weight('bold')
        if col == 0:
            cell.set_text_props(weight='bold')
            cell.set_facecolor('#F9FAFB')
    return table

def render_simple_table(metrics: Dict[str, Any]):
    tr = metrics.get("transport", {})
    oi = metrics.get("oidc", {})
    sy = metrics.get("system", {})

    data = [
        ["Handshake latency", "214.8 ms", "613.2 ms", "639.0 ms", f"{tr.get('handshake_latency', {}).get('mean')} ms"],
        ["Handshake bytes", "2.15 KB", "11.18 KB", "9.07 KB", f"{tr.get('handshake_size', {}).get('total'):.2f} KB"],
        ["End-to-end login", "365.2 ms", "828.4 ms", "712.1 ms", f"{oi.get('e2e_latency', {}).get('total')} ms"],
        ["Token sign", "0.85 ms", "0.16 ms", "0.16 ms", f"{tr.get('crypto_timings', {}).get('ml_dsa_65_sign')} ms"],
        ["Token verify", "0.05 ms", "0.14 ms", "0.14 ms", f"{tr.get('crypto_timings', {}).get('ml_dsa_65_verify')} ms"],
        ["Resource access latency", "204.2 ms", "412.1 ms", "388.4 ms", f"{oi.get('e2e_latency', {}).get('resource_access')} ms"],
        ["CPU / 100 auths", "1.2%", "5.6%", "3.8%", sy.get("cpu_utilization", {}).get("idp_pct")]
    ]
    
    fig, ax = plt.subplots(figsize=(14, 8))
    columns = ["Metric", "Normal TLS", "PQ-TLS (Sig)", "KEM TLS", "QuantumID"]
    draw_generic_table(ax, "QuantumID Performance Benchmarks", columns, data, highlight_col=4)
    
    out_path = COMPARISON_DIR / "presentation_benchmark_table.png"
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[*] Simple table generated: {out_path}")

def render_report_png(metrics: Dict[str, Any]):
    tr = metrics.get("transport", {})
    t_lat = tr.get("handshake_latency", {})
    t_size = tr.get("handshake_size", {})
    t_cry = tr.get("crypto_timings", {})

    section_a = [
        ["Handshake (Mean)", "214.8 ms", "613.2 ms", "639.0 ms", f"{t_lat.get('mean')} ms"],
        ["Handshake (p99)", "420.5 ms", "1250.4 ms", "1310.2 ms", f"{t_lat.get('p99')} ms"],
        ["Handshake (3% Loss)", "580.4 ms", "1820.2 ms", "1940.5 ms", f"{t_lat.get('loss_3pct')} ms"],
        ["Total Handshake Size", "2.15 KB", "11.18 KB", "9.07 KB", f"{t_size.get('total'):.2f} KB"],
        ["TCP Segments", "2", "8", "7", str(t_size.get("tcp_segments"))],
        ["ML-KEM-768 Encap", "N/A", "0.24 ms", "0.24 ms", f"{t_cry.get('ml_kem_768_encap')} ms"],
        ["ML-DSA-65 Sign", "N/A", "0.16 ms", "0.16 ms", f"{t_cry.get('ml_dsa_65_sign')} ms"],
    ]

    oi = metrics.get("oidc", {})
    o_lat = oi.get("e2e_latency", {})
    o_gen = oi.get("token_gen", {})
    o_ver = oi.get("token_verify", {})

    section_b = [
        ["End-to-End Login", "365.2 ms", "828.4 ms", "712.1 ms", f"{o_lat.get('total')} ms"],
        [" - Secure Transport", "214.8 ms", "613.2 ms", "639.0 ms", f"{o_lat.get('secure_transport')} ms"],
        [" - Token Generation", "8.4 ms", "24.5 ms", "24.5 ms", f"{o_lat.get('token_gen')} ms"],
        ["Token Sign (Dilithium3)", "N/A", "0.16 ms", "0.16 ms", f"{o_gen.get('sign_dilithium3')} ms"],
        ["Token Verify (Dilithium3)", "N/A", "0.14 ms", "0.14 ms", f"{o_ver.get('dilithium_verify')} ms"],
    ]

    sy = metrics.get("system", {})
    s_cpu = sy.get("cpu_utilization", {})
    s_mem = sy.get("memory_usage", {})
    s_sca = sy.get("scalability", {})

    section_c = [
        ["CPU Usage (IdP)", "1.2%", "5.6%", "3.8%", s_cpu.get("idp_pct")],
        ["Memory (Peak RSS)", "14.2 MB", "84.5 MB", "62.4 MB", f"{s_mem.get('peak_rss_mb')} MB"],
        ["Throughput (100 users)", "1840/s", "420/s", "580/s", f"{s_sca.get('throughput_100_users')}/s"],
        ["Queue Latency", "0.2 ms", "12.4 ms", "8.2 ms", f"{s_sca.get('queue_latency_ms')} ms"],
    ]

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(14, 18))
    plt.subplots_adjust(hspace=0.4)
    columns = ["Metric", "Normal TLS", "PQ-TLS (Sig)", "KEM TLS", "QuantumID"]
    
    draw_generic_table(ax1, "SECTION A: KEMTLS TRANSPORT PERFORMANCE", columns, section_a, highlight_col=4)
    draw_generic_table(ax2, "SECTION B: OIDC PROTOCOL & IDENTITY OVERHEAD", columns, section_b, highlight_col=4)
    draw_generic_table(ax3, "SECTION C: SYSTEM EFFICIENCY & SCALABILITY", columns, section_c, highlight_col=4)

    plt.figtext(0.5, 0.02, "Research Scenario: SLOW WAN (100ms RTT) | Cited: Schwabe 2022, Chen 2025", 
                ha="center", fontsize=10, color="#6B7280", style='italic')

    out_path = COMPARISON_DIR / "presentation_benchmark_report.png"
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[*] Multi-section report generated: {out_path}")

def main():
    metrics = _load_json(METRICS_JSON)
    if not metrics:
        print("Master metrics JSON missing. Run generate_presentation_results.py first.")
        return
    
    render_simple_table(metrics)
    render_report_png(metrics)

if __name__ == "__main__":
    main()
