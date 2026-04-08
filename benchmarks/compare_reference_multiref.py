from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import matplotlib.pyplot as plt


SCRIPT_DIR = Path(__file__).resolve().parent
REFERENCE_PATH = SCRIPT_DIR / "reference" / "reference_values.json"
RESULTS_DIR = SCRIPT_DIR / "results"
COMPARISON_DIR = SCRIPT_DIR / "comparison"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as file_handle:
        return list(csv.DictReader(file_handle))


def _latest_run_id(raw_root: Path) -> Optional[str]:
    candidates = [path for path in raw_root.iterdir() if path.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    return candidates[0].name


def _mean(rows: List[Dict[str, str]], field: str, *, handshake_mode: Optional[str] = None) -> float:
    values: List[float] = []
    for row in rows:
        if handshake_mode is not None and row.get("handshake_mode") != handshake_mode:
            continue
        raw = row.get(field)
        if raw in (None, ""):
            continue
        try:
            values.append(float(raw))
        except ValueError:
            continue
    if not values:
        return 0.0
    return sum(values) / len(values)


def _trim_first_iteration(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Drop the earliest iteration row when possible to reduce cold-start skew."""
    if len(rows) <= 1:
        return rows

    def _iteration_value(row: Dict[str, str]) -> int:
        raw = row.get("iteration", "")
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    first_row = min(rows, key=_iteration_value)
    first_index = rows.index(first_row)
    return rows[:first_index] + rows[first_index + 1 :]


def _core_auth_mean(rows: List[Dict[str, str]]) -> float:
    values: List[float] = []
    for row in rows:
        try:
            values.append(float(row.get("t_authorize_ms", "")) + float(row.get("t_token_ms", "")))
        except (TypeError, ValueError):
            continue
    if not values:
        return 0.0
    return sum(values) / len(values)


def _full_cycle_mean(rows: List[Dict[str, str]]) -> float:
    values: List[float] = []
    for row in rows:
        raw_full = row.get("t_full_cycle_ms", "")
        raw_legacy = row.get("t_auth_total_ms", "")
        try:
            if raw_full not in (None, ""):
                values.append(float(raw_full))
            elif raw_legacy not in (None, ""):
                # Backward compatibility: old runs stored full-cycle in t_auth_total_ms.
                values.append(float(raw_legacy))
        except (TypeError, ValueError):
            continue
    if not values:
        return 0.0
    return sum(values) / len(values)


def _local_metrics(raw_dir: Path) -> Dict[str, float]:
    handshake_rows = _load_csv_rows(raw_dir / "handshake_results.csv")
    oidc_rows = _load_csv_rows(raw_dir / "oidc_results.csv")
    crypto_rows = _load_csv_rows(raw_dir / "crypto_results.csv")

    baseline_oidc_rows = [row for row in oidc_rows if row.get("handshake_mode") == "baseline"]
    baseline_oidc_trimmed = _trim_first_iteration(baseline_oidc_rows)

    return {
        "kemtls_handshake_ms": _mean(handshake_rows, "hct_client_ms", handshake_mode="baseline"),
        "kemtls_pdk_handshake_ms": _mean(handshake_rows, "hct_client_ms", handshake_mode="pdk"),
        "t_authorize_ms": _mean(baseline_oidc_trimmed, "t_authorize_ms"),
        "t_token_ms": _mean(baseline_oidc_trimmed, "t_token_ms"),
        "t_auth_total_ms": _core_auth_mean(baseline_oidc_trimmed),
        "t_full_cycle_ms": _full_cycle_mean(baseline_oidc_trimmed),
        "crypto_latency_us": _mean(crypto_rows, "latency_us"),
    }


def _build_report(local_metrics: Dict[str, float], references: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    comparison_rows: List[Dict[str, Any]] = []
    for ref in references:
        values = ref.get("values", {})
        for metric_name, cited_value in values.items():
            local_value = local_metrics.get(metric_name, 0.0)
            delta_pct = ((local_value - cited_value) / cited_value * 100.0) if cited_value else 0.0
            comparison_rows.append(
                {
                    "reference_id": ref.get("id"),
                    "source": ref.get("source"),
                    "year": ref.get("year"),
                    "metric": metric_name,
                    "cited_value": cited_value,
                    "local_value": round(local_value, 4),
                    "delta_pct": round(delta_pct, 2),
                    "environment": ref.get("environment"),
                    "measured": ref.get("measured", False),
                }
            )
    return {"local_metrics": local_metrics, "comparisons": comparison_rows}


def _write_markdown(report: Dict[str, Any], out_path: Path) -> None:
    lines = [
        "# Reference Comparison",
        "",
        "| Source | Year | Metric | Cited | Local | Delta % |",
        "|---|---:|---|---:|---:|---:|",
    ]
    for row in report["comparisons"]:
        lines.append(
            f"| {row['source']} | {row['year']} | {row['metric']} | {row['cited_value']:.4f} | {row['local_value']:.4f} | {row['delta_pct']:.2f} |"
        )
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _plot(report: Dict[str, Any], out_path: Path) -> None:
    rows = report["comparisons"]
    if not rows:
        return
    labels = [f"{row['source']}:{row['metric']}" for row in rows]
    cited = [float(row["cited_value"]) for row in rows]
    local = [float(row["local_value"]) for row in rows]
    x = list(range(len(labels)))
    width = 0.4
    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.9), 4.5))
    ax.bar([idx - width / 2 for idx in x], cited, width, label="Reference")
    ax.bar([idx + width / 2 for idx in x], local, width, label="Local")
    ax.set_title("Local Benchmarks vs Reference Values")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=40, ha="right")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare local benchmark runs with reference values")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--results-dir", default=str(RESULTS_DIR))
    parser.add_argument("--reference", default=str(REFERENCE_PATH))
    parser.add_argument("--output-dir", default=str(COMPARISON_DIR))
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    raw_root = results_dir / "raw"
    run_id = args.run_id or _latest_run_id(raw_root)
    if not run_id:
        raise SystemExit("No benchmark runs found under benchmarks/results/raw")

    raw_dir = raw_root / run_id
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    references = _load_json(Path(args.reference)).get("references", [])
    report = _build_report(_local_metrics(raw_dir), references)

    (output_dir / f"{run_id}_comparison.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_markdown(report, output_dir / f"{run_id}_comparison.md")
    _plot(report, output_dir / f"{run_id}_comparison.png")
    print(f"[*] Comparison report written for run_id={run_id} in {output_dir}")


if __name__ == "__main__":
    main()
