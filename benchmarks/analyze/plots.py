from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List

import matplotlib.pyplot as plt


def _load_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _group_avg(rows: List[Dict[str, str]], key_col: str, value_col: str) -> Dict[str, float]:
    sums: Dict[str, float] = {}
    counts: Dict[str, int] = {}
    for row in rows:
        k = row.get(key_col, "")
        v = row.get(value_col, "")
        if not k or not v:
            continue
        try:
            f = float(v)
        except ValueError:
            continue
        sums[k] = sums.get(k, 0.0) + f
        counts[k] = counts.get(k, 0) + 1
    return {k: sums[k] / counts[k] for k in sums}


def _bar(data: Dict[str, float], title: str, out_file: Path) -> None:
    if not data:
        return
    labels = list(data.keys())
    values = [data[k] for k in labels]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(labels, values)
    ax.set_title(title)
    ax.tick_params(axis="x", labelrotation=30)
    fig.tight_layout()
    fig.savefig(out_file, dpi=180)
    plt.close(fig)


def _group_avg_expr(rows: List[Dict[str, str]], key_col: str, value_fn) -> Dict[str, float]:
    sums: Dict[str, float] = {}
    counts: Dict[str, int] = {}
    for row in rows:
        k = row.get(key_col, "")
        if not k:
            continue
        value = value_fn(row)
        if value is None:
            continue
        sums[k] = sums.get(k, 0.0) + value
        counts[k] = counts.get(k, 0) + 1
    return {k: sums[k] / counts[k] for k in sums}


def _core_auth_value(row: Dict[str, str]):
    try:
        return float(row.get("t_authorize_ms", "")) + float(row.get("t_token_ms", ""))
    except ValueError:
        return None


def _full_cycle_value(row: Dict[str, str]):
    raw_full = row.get("t_full_cycle_ms")
    raw_legacy = row.get("t_auth_total_ms")
    try:
        if raw_full not in (None, ""):
            return float(raw_full)
        if raw_legacy not in (None, ""):
            # Backward compatibility: old runs stored full-cycle in t_auth_total_ms.
            return float(raw_legacy)
    except ValueError:
        return None
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate benchmark plots")
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    crypto = _load_rows(raw_dir / "crypto_results.csv")
    handshake = _load_rows(raw_dir / "handshake_results.csv")
    oidc = _load_rows(raw_dir / "oidc_results.csv")
    load = _load_rows(raw_dir / "load_results.csv")
    artifacts = _load_rows(raw_dir / "artifacts_results.csv")

    _bar(_group_avg(crypto, "operation", "latency_us"), "Crypto Latency (us)", out_dir / "crypto_latency.png")
    handshake_group = "handshake_mode" if handshake and "handshake_mode" in handshake[0] else "scenario"
    oidc_group = "handshake_mode" if oidc and "handshake_mode" in oidc[0] else "scenario"
    load_group = "concurrency"
    _bar(_group_avg(handshake, handshake_group, "hct_client_ms"), "Handshake HCT by Mode (ms)", out_dir / "handshake_hct.png")
    _bar(_group_avg_expr(oidc, oidc_group, _core_auth_value), "OIDC Core Auth Time by Mode (ms)", out_dir / "oidc_auth_total.png")
    _bar(_group_avg_expr(oidc, oidc_group, _full_cycle_value), "OIDC Full Cycle Time by Mode (ms)", out_dir / "oidc_full_cycle.png")
    _bar(_group_avg(load, "concurrency", "throughput_req_sec"), "Load Throughput by Concurrency", out_dir / "load_throughput.png")
    _bar(_group_avg(artifacts, "scenario", "s_id_token_bytes"), "ID Token Size by Mode (bytes)", out_dir / "artifact_id_token_size.png")


if __name__ == "__main__":
    main()
