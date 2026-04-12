import csv
import json
import statistics
import argparse
from pathlib import Path

def get_stats(values):
    if not values: return "0.0/0.0/0.0"
    v = sorted(values)
    p50 = statistics.median(v)
    p95 = v[min(len(v)-1, int(len(v)*0.95))]
    p99 = v[min(len(v)-1, int(len(v)*0.99))]
    return f"{p50:.2f}/{p95:.2f}/{p99:.2f}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    
    base_path = Path("benchmarks/results/raw") / args.run_id
    out_path = Path("benchmarks/results")
    out_path.mkdir(parents=True, exist_ok=True)
    
    # 1. handshake.csv
    hs_raw = list(csv.DictReader(open(base_path / "handshake.csv")))
    hs_summary = []
    # Group by mode + rtt
    groups = {}
    for r in hs_raw:
        k = (r["protocol"], f"{r['handshake_mode']}_rtt{r['rtt_ms']}ms")
        if k not in groups: groups[k] = {"lat": [], "bytes": [], "seg": []}
        groups[k]["lat"].append(float(r["latency_ms"]))
        groups[k]["bytes"].append(float(r["bytes_total"]))
        groups[k]["seg"].append(float(r["segments"]))
        
    for (proto, scen), d in groups.items():
        hs_summary.append({
            "protocol": proto,
            "scenario": scen,
            "latency_ms (p50/p95/p99)": get_stats(d["lat"]),
            "bytes_total": f"{statistics.mean(d['bytes']):.0f}",
            "segments": f"{statistics.mean(d['seg']):.1f}"
        })
        
    with open(out_path / "handshake.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["protocol", "scenario", "latency_ms (p50/p95/p99)", "bytes_total", "segments"])
        w.writeheader()
        w.writerows(hs_summary)

    # 2. oidc.csv
    oidc_raw = list(csv.DictReader(open(base_path / "oidc.csv")))
    oidc_summary = []
    groups = {}
    for r in oidc_raw:
        k = (r["protocol"], r["scenario"])
        if k not in groups: groups[k] = {"auth": [], "token": [], "verify": [], "res": []}
        groups[k]["auth"].append(float(r["auth_total_ms"]))
        groups[k]["token"].append(float(r["token_ms"]))
        groups[k]["verify"].append(float(r["verify_ms"]))
        groups[k]["res"].append(float(r["resource_ms"]))
        
    for (proto, scen), d in groups.items():
        oidc_summary.append({
            "protocol": proto,
            "scenario": scen,
            "auth_total_ms": f"{statistics.mean(d['auth']):.2f}",
            "token_ms": f"{statistics.mean(d['token']):.2f}",
            "verify_ms": f"{statistics.mean(d['verify']):.2f}",
            "resource_ms": f"{statistics.mean(d['res']):.2f}"
        })
        
    with open(out_path / "oidc.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["protocol", "scenario", "auth_total_ms", "token_ms", "verify_ms", "resource_ms"])
        w.writeheader()
        w.writerows(oidc_summary)

    # 3. system.csv
    sys_raw = list(csv.DictReader(open(base_path / "system.csv")))
    with open(out_path / "system.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["protocol", "cpu_pct", "memory_mb", "throughput_rps"])
        w.writeheader()
        for r in sys_raw:
            w.writerow({
                "protocol": f"{r['protocol']}_{r['scenario']}_c{r['concurrency']}",
                "cpu_pct": r["cpu_pct"],
                "memory_mb": r["memory_mb"],
                "throughput_rps": r["throughput_rps"]
            })

    print(f"[*] Summary CSVs written to {out_path}")

if __name__ == "__main__":
    main()
