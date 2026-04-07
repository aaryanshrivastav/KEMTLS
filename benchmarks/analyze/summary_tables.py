from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List

from stats import summarize


METRIC_COLUMNS = [
    "latency_us",
    "hct_client_ms",
    "hct_server_ms",
    "ttfb_ms",
    "t_auth_total_ms",
    "t_token_ms",
    "t_userinfo_ms",
    "throughput_req_sec",
    "avg_latency_ms",
]


def _load_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _summarize_rows(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, float]]:
    result: Dict[str, Dict[str, float]] = {}
    for col in METRIC_COLUMNS:
        values: List[float] = []
        for row in rows:
            raw = row.get(col)
            if raw is None or raw == "":
                continue
            try:
                values.append(float(raw))
            except ValueError:
                pass
        if values:
            result[col] = summarize(values)
    return result


def _to_markdown(summary_by_file: Dict[str, Dict[str, Dict[str, float]]]) -> str:
    lines = ["# Benchmark Summary", "", "| File | Metric | Mean | P95 | P99 |", "|---|---:|---:|---:|---:|"]
    for file_name, metrics in summary_by_file.items():
        for metric, stats in metrics.items():
            lines.append(
                f"| {file_name} | {metric} | {stats['mean']:.4f} | {stats['p95']:.4f} | {stats['p99']:.4f} |"
            )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate benchmark summary tables")
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = [
        "crypto_results.csv",
        "handshake_results.csv",
        "oidc_results.csv",
        "load_results.csv",
    ]

    summary_by_file: Dict[str, Dict[str, Dict[str, float]]] = {}
    for name in files:
        rows = _load_csv(raw_dir / name)
        if rows:
            summary_by_file[name] = _summarize_rows(rows)

    (out_dir / "summary_tables.json").write_text(json.dumps(summary_by_file, indent=2), encoding="utf-8")
    (out_dir / "summary_tables.md").write_text(_to_markdown(summary_by_file), encoding="utf-8")


if __name__ == "__main__":
    main()
