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
from typing import Any, Callable, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from crypto.aead import open_, seal
from crypto.ml_dsa import MLDSA65
from crypto.ml_kem import MLKEM768


def _measure_latency_us(operation: Callable[[], Any]) -> tuple[float, Any]:
    start_ns = time.perf_counter_ns()
    result = operation()
    latency_us = (time.perf_counter_ns() - start_ns) / 1000.0
    return latency_us, result


def _percentile(values: List[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * (percentile / 100.0)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _summarize(latencies: List[float]) -> Dict[str, float]:
    if not latencies:
        return {}
    return {
        "avg_us": statistics.mean(latencies),
        "median_us": statistics.median(latencies),
        "p95_us": _percentile(latencies, 95.0),
        "p99_us": _percentile(latencies, 99.0),
        "min_us": min(latencies),
        "max_us": max(latencies),
    }


def _run_series(
    *,
    run_id: str,
    environment_profile: str,
    primitive: str,
    operation: str,
    repeat: int,
    measurement: Callable[[], Any],
    writer: csv.DictWriter,
) -> List[float]:
    latencies: List[float] = []
    for iteration in range(repeat):
        latency_us, _ = _measure_latency_us(measurement)
        latencies.append(latency_us)
        writer.writerow(
            {
                "run_id": run_id,
                "primitive": primitive,
                "operation": operation,
                "latency_us": round(latency_us, 3),
                "iteration": iteration,
                "environment_profile": environment_profile,
            }
        )
    return latencies


def _load_config(config_path: Path) -> Dict[str, Any]:
    if not config_path.exists():
        return {}
    return json.loads(config_path.read_text(encoding="utf-8"))


def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    warmup = int(config.get("warmup", 50))
    repeat = int(config.get("repeat", 1000))
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw_dir / "crypto_results.csv"
    summary_path = raw_dir / "crypto_summary.json"

    print("Running crypto benchmark suite...")
    print(f"[*] run_id={run_id}")
    print(f"[*] environment_profile={environment_profile}")
    print(f"[*] warmup={warmup} repeat={repeat}")

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "run_id",
                "primitive",
                "operation",
                "latency_us",
                "iteration",
                "environment_profile",
            ],
        )
        writer.writeheader()

        for _ in range(warmup):
            kem_pk, kem_sk = MLKEM768.generate_keypair()
            kem_ct, _ = MLKEM768.encapsulate(kem_pk)
            MLKEM768.decapsulate(kem_sk, kem_ct)

            sig_pk, sig_sk = MLDSA65.generate_keypair()
            sig_msg = os.urandom(64)
            sig_sig = MLDSA65.sign(sig_sk, sig_msg)
            MLDSA65.verify(sig_pk, sig_msg, sig_sig)

            aead_key = os.urandom(32)
            aead_nonce = os.urandom(12)
            aead_plaintext = os.urandom(1024)
            aead_aad = b"warmup-aad"
            aead_ct = seal(aead_key, aead_nonce, aead_plaintext, aead_aad)
            open_(aead_key, aead_nonce, aead_ct, aead_aad)

        summaries: Dict[str, Dict[str, float]] = {}

        kem_pk, kem_sk = MLKEM768.generate_keypair()
        kem_ct, _ = MLKEM768.encapsulate(kem_pk)
        summaries["ml_kem_keygen"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ML-KEM-768",
                operation="keygen",
                repeat=repeat,
                measurement=MLKEM768.generate_keypair,
                writer=writer,
            )
        )
        summaries["ml_kem_encapsulate"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ML-KEM-768",
                operation="encapsulate",
                repeat=repeat,
                measurement=lambda pk=kem_pk: MLKEM768.encapsulate(pk),
                writer=writer,
            )
        )
        summaries["ml_kem_decapsulate"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ML-KEM-768",
                operation="decapsulate",
                repeat=repeat,
                measurement=lambda sk=kem_sk, ct=kem_ct: MLKEM768.decapsulate(sk, ct),
                writer=writer,
            )
        )

        sig_pk, sig_sk = MLDSA65.generate_keypair()
        sig_msg = b"benchmark message for ML-DSA-65"
        sig_sig = MLDSA65.sign(sig_sk, sig_msg)
        summaries["ml_dsa_keygen"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ML-DSA-65",
                operation="keygen",
                repeat=repeat,
                measurement=MLDSA65.generate_keypair,
                writer=writer,
            )
        )
        summaries["ml_dsa_sign"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ML-DSA-65",
                operation="sign",
                repeat=repeat,
                measurement=lambda sk=sig_sk, msg=sig_msg: MLDSA65.sign(sk, msg),
                writer=writer,
            )
        )
        summaries["ml_dsa_verify"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ML-DSA-65",
                operation="verify",
                repeat=repeat,
                measurement=lambda pk=sig_pk, msg=sig_msg, sig=sig_sig: MLDSA65.verify(pk, msg, sig),
                writer=writer,
            )
        )

        aead_key = os.urandom(32)
        aead_nonce = os.urandom(12)
        aead_plaintext = os.urandom(1024)
        aead_aad = b"benchmark-aad"
        aead_ct = seal(aead_key, aead_nonce, aead_plaintext, aead_aad)
        summaries["aead_seal_1kb"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ChaCha20-Poly1305",
                operation="seal_1kb",
                repeat=repeat,
                measurement=lambda key=aead_key, nonce=aead_nonce, plaintext=aead_plaintext, aad=aead_aad: seal(key, nonce, plaintext, aad),
                writer=writer,
            )
        )
        summaries["aead_open_1kb"] = _summarize(
            _run_series(
                run_id=run_id,
                environment_profile=environment_profile,
                primitive="ChaCha20-Poly1305",
                operation="open_1kb",
                repeat=repeat,
                measurement=lambda key=aead_key, nonce=aead_nonce, ciphertext=aead_ct, aad=aead_aad: open_(key, nonce, ciphertext, aad),
                writer=writer,
            )
        )

    summary_path.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(f"[*] Crypto benchmarks saved to {csv_path}")
    print(f"[*] Crypto summary saved to {summary_path}")
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real crypto benchmarks")
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repeat", type=int, default=None)
    parser.add_argument("--warmup", type=int, default=None)
    parser.add_argument("--environment-profile", default=None)
    args = parser.parse_args()

    config_path = (SCRIPT_DIR / args.config).resolve()
    config = _load_config(config_path)
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
