from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

from crypto.ml_dsa import MLDSA65
from kemtls.certs import create_certificate
from kemtls.handshake import ClientHandshake, ServerHandshake
from kemtls.pdk import PDKTrustStore
from telemetry.collector import KEMTLSHandshakeCollector
from utils.encoding import base64url_decode
from utils.helpers import get_timestamp


def _load_keys() -> Dict[str, Any]:
    base_dir = ROOT_DIR / "keys"
    with (base_dir / "ca" / "ca_keys.json").open("r", encoding="utf-8") as file_handle:
        ca_config = json.load(file_handle)
    with (base_dir / "auth_server" / "as_config.json").open("r", encoding="utf-8") as file_handle:
        as_config = json.load(file_handle)
    with (base_dir / "pdk" / "pdk_manifest.json").open("r", encoding="utf-8") as file_handle:
        pdk_manifest = json.load(file_handle)

    pdk_store = PDKTrustStore()
    for entry in pdk_manifest:
        pdk_store.add_entry(
            entry["key_id"],
            entry["identity"],
            base64url_decode(entry["ml_kem_public_key"]),
            metadata=entry.get("metadata"),
        )

    return {
        "ca_pk": base64url_decode(ca_config["public_key"]),
        "server_identity": "auth-server",
        "server_sk": base64url_decode(as_config["longterm_sk"]),
        "server_cert": as_config["certificate"],
        "pdk_store": pdk_store,
        "pdk_key_id": as_config.get("pdk_key_id", "as-key-1"),
    }


def _rss_bytes() -> int:
    if psutil is None:
        return 0
    return int(psutil.Process().memory_info().rss)


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "avg": statistics.mean(values),
        "median": statistics.median(values),
        "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
    }


def _run_handshake(mode: str, keys: Dict[str, Any]) -> Dict[str, Any]:
    client_collector = KEMTLSHandshakeCollector()
    server_collector = KEMTLSHandshakeCollector()

    client = ClientHandshake(
        expected_identity=keys["server_identity"],
        ca_pk=keys["ca_pk"],
        pdk_store=keys["pdk_store"],
        mode=mode,
        collector=client_collector,
    )
    server = ServerHandshake(
        server_identity=keys["server_identity"],
        server_lt_sk=keys["server_sk"],
        cert=keys["server_cert"],
        pdk_key_id=keys["pdk_key_id"],
        collector=server_collector,
    )

    rss_start = _rss_bytes()
    client_collector.start_hct()
    server_collector.start_hct()
    t_start_ns = time.perf_counter_ns()

    client_hello = client.client_hello()
    server_hello = server.process_client_hello(client_hello)
    client_key_exchange, client_session = client.process_server_hello(server_hello)
    server_finished = server.process_client_key_exchange(client_key_exchange)
    final_session = client.process_server_finished(server_finished, client_session)
    client_finished = client.client_finished()
    server.verify_client_finished(client_finished)

    t_end_ns = time.perf_counter_ns()
    client_collector.end_hct()
    server_collector.end_hct()

    client_metrics = client_collector.get_metrics()
    server_metrics = server_collector.get_metrics()

    return {
        "mode": client_metrics["mode"],
        "hct_client_ms": client_metrics["hct_ms"],
        "hct_server_ms": server_metrics["hct_ms"],
        "ttfb_ms": (t_end_ns - t_start_ns) / 1_000_000,
        "bytes_total": client_metrics["total_handshake_bytes"],
        "tcp_segments": max(1, (client_metrics["total_handshake_bytes"] + 1439) // 1440),
        "cpu_cycles": 0,
        "rss_delta": _rss_bytes() - rss_start,
        "session": final_session,
    }


def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    warmup = int(config.get("warmup", 50))
    repeat = int(config.get("repeat", 1000))
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw_dir / "handshake_results.csv"
    summary_path = raw_dir / "handshake_summary.json"

    keys = _load_keys()
    print("Running handshake benchmark suite...")
    print(f"[*] run_id={run_id}")
    print(f"[*] environment_profile={environment_profile}")
    print(f"[*] warmup={warmup} repeat={repeat}")

    for _ in range(warmup):
        _run_handshake("baseline", keys)
        _run_handshake("pdk", keys)

    rows: List[Dict[str, Any]] = []
    summaries: Dict[str, Dict[str, float]] = {}

    for mode in ("baseline", "pdk"):
        hct_client_values: List[float] = []
        hct_server_values: List[float] = []
        ttfb_values: List[float] = []
        total_bytes_values: List[float] = []

        for iteration in range(repeat):
            result = _run_handshake(mode, keys)
            hct_client_values.append(float(result["hct_client_ms"]))
            hct_server_values.append(float(result["hct_server_ms"]))
            ttfb_values.append(float(result["ttfb_ms"]))
            total_bytes_values.append(float(result["bytes_total"]))

            rows.append(
                {
                    "run_id": run_id,
                    "protocol": "KEMTLS",
                    "scenario": mode,
                    "hct_client_ms": round(float(result["hct_client_ms"]), 3),
                    "hct_server_ms": round(float(result["hct_server_ms"]), 3),
                    "ttfb_ms": round(float(result["ttfb_ms"]), 3),
                    "bytes_total": int(result["bytes_total"]),
                    "tcp_segments": int(result["tcp_segments"]),
                    "cpu_cycles": int(result["cpu_cycles"]),
                    "rss_delta": int(result["rss_delta"]),
                    "iteration": iteration,
                    "environment_profile": environment_profile,
                }
            )

        summaries[mode] = {
            "hct_client": _stats(hct_client_values),
            "hct_server": _stats(hct_server_values),
            "ttfb": _stats(ttfb_values),
            "bytes_total": _stats(total_bytes_values),
        }

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "run_id",
                "protocol",
                "scenario",
                "hct_client_ms",
                "hct_server_ms",
                "ttfb_ms",
                "bytes_total",
                "tcp_segments",
                "cpu_cycles",
                "rss_delta",
                "iteration",
                "environment_profile",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(f"[*] Handshake benchmarks saved to {csv_path}")
    print(f"[*] Handshake summary saved to {summary_path}")
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real handshake benchmarks")
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repeat", type=int, default=None)
    parser.add_argument("--warmup", type=int, default=None)
    parser.add_argument("--environment-profile", default=None)
    args = parser.parse_args()

    config_path = (SCRIPT_DIR / args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    if args.results_dir is not None:
        config["results_dir"] = args.results_dir
    if args.run_id is not None:
        config["run_id"] = args.run_id
    if args.repeat is not None:
        config["repeat"] = args.repeat
    if args.warmup is not None:
        config["warmup"] = args.warmup
    if args.environment_profile is not None:
        config["environment_profile"] = args.environment_profile

    run_benchmark(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBenchmark stopped")
