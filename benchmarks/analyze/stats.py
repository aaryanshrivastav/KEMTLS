from __future__ import annotations

import csv
import json
import statistics
import argparse
from pathlib import Path
from typing import Dict, List, Any

def calculate_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
    
    ordered = sorted(values)
    return {
        "p50": statistics.median(values),
        "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
        "p99": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.99))],
        "mean": statistics.mean(values)
    }

def process_handshake(csv_path: Path):
    if not csv_path.exists():
        return None
    
    data = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
            
    # Group by mode and RTT
    groups = {}
    for row in data:
        key = (row["handshake_mode"], row["rtt_ms"])
        if key not in groups:
            groups[key] = []
        groups[key].append(float(row["latency_ms"]))
        
    results = {}
    for key, values in groups.items():
        results[f"{key[0]}_rtt{key[1]}"] = calculate_stats(values)
    return results

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    
    base_path = Path("benchmarks/results/raw") / args.run_id
    
    handshake_stats = process_handshake(base_path / "handshake.csv")
    
    if handshake_stats:
        output_path = base_path / "stats_handshake.json"
        output_path.write_text(json.dumps(handshake_stats, indent=2))
        print(f"[*] Stats saved to {output_path}")

if __name__ == "__main__":
    main()
