from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple
import importlib

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from client.kemtls_http_client import KEMTLSHttpClient
from crypto.key_schedule import compute_transcript_hash, hkdf_extract, hkdf_expand_label
from crypto.ml_dsa import MLDSA65
from crypto.ml_kem import MLKEM768
from kemtls._http_bridge import parse_http_request
from kemtls.certs import create_certificate
from kemtls.handshake import ClientHandshake, ServerHandshake
from oidc.jwt_handler import PQJWT
from rust_ext import jwt as rust_jwt
from rust_ext import get_build_profile
from utils.encoding import base64url_encode
from utils.serialization import deserialize_message, serialize_message


def _load_config(config_path: Path) -> Dict[str, Any]:
    if not config_path.exists():
        return {}
    return json.loads(config_path.read_text(encoding="utf-8"))


def _percentile(values: List[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int((len(ordered) - 1) * percentile)
    return float(ordered[index])


def _summarize(samples_us: List[float]) -> Dict[str, float]:
    return {
        "avg_us": float(statistics.mean(samples_us)),
        "median_us": float(statistics.median(samples_us)),
        "p95_us": _percentile(samples_us, 0.95),
        "min_us": float(min(samples_us)),
        "max_us": float(max(samples_us)),
    }


def _measure(operation: Callable[[], Any], warmup: int, repeat: int) -> Dict[str, Any]:
    for _ in range(warmup):
        operation()

    samples_us: List[float] = []
    for _ in range(repeat):
        start_ns = time.perf_counter_ns()
        operation()
        duration_us = (time.perf_counter_ns() - start_ns) / 1_000.0
        samples_us.append(duration_us)

    return {
        "repeat": repeat,
        "warmup": warmup,
        "stats": _summarize(samples_us),
        "samples_us": [round(value, 3) for value in samples_us],
    }


def _measure_batched(operation: Callable[[], Any], inner_loops: int, warmup: int, repeat: int) -> Dict[str, Any]:
    """Measure amortized cost by executing many operations per timed sample."""
    for _ in range(warmup):
        for _ in range(inner_loops):
            operation()

    per_op_samples_us: List[float] = []
    for _ in range(repeat):
        start_ns = time.perf_counter_ns()
        for _ in range(inner_loops):
            operation()
        total_us = (time.perf_counter_ns() - start_ns) / 1_000.0
        per_op_samples_us.append(total_us / float(inner_loops))

    return {
        "repeat": repeat,
        "warmup": warmup,
        "inner_loops": inner_loops,
        "stats": _summarize(per_op_samples_us),
        "samples_us": [round(value, 3) for value in per_op_samples_us],
    }


@contextmanager
def _rust_backend_mode(enabled: bool):
    import rust_ext

    original_core = rust_ext._core
    original_flag = rust_ext.HAS_RUST_BACKEND

    if enabled and original_core is None:
        raise RuntimeError("Rust backend is not installed; cannot run rust-enabled benchmark mode")

    if enabled:
        rust_ext._core = original_core
        rust_ext.HAS_RUST_BACKEND = True
    else:
        rust_ext._core = None
        rust_ext.HAS_RUST_BACKEND = False

    try:
        yield
    finally:
        rust_ext._core = original_core
        rust_ext.HAS_RUST_BACKEND = original_flag


def _build_test_materials() -> Dict[str, Any]:
    serialization_payload = {
        "kind": "bench",
        "n": 42,
        "items": ["a", "b", "c", {"x": 1, "y": 2}],
        "flags": {"r": True, "p": False},
    }
    transcript_chunks = [b"client-hello", b"server-hello", b"client-key-exchange"]

    http_request = (
        b"POST /token HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 18\r\n\r\n"
        b'{"grant":"code"}'
    )
    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 21\r\n\r\n"
        b'{"status":"success"}'
    )
    http_client = KEMTLSHttpClient()

    header_b64 = base64url_encode(serialize_message({"alg": "ML-DSA-65", "typ": "JWT"}))
    payload_b64 = base64url_encode(
        serialize_message({"sub": "alice", "cnf": {"kmt": "kemtls", "kbh": "abc123"}})
    )
    jwt_token = f"{header_b64}.{payload_b64}.sig"
    jwt_parser = PQJWT()

    ca_pk, ca_sk = MLDSA65.generate_keypair()
    server_kem_pk, server_kem_sk = MLKEM768.generate_keypair()
    now = int(time.time())
    cert = create_certificate(
        subject="auth-server",
        kem_pk=server_kem_pk,
        ca_sk=ca_sk,
        issuer="test-ca",
        valid_from=now - 60,
        valid_to=now + 3600,
    )

    return {
        "serialization_payload": serialization_payload,
        "transcript_chunks": transcript_chunks,
        "http_request": http_request,
        "http_response": http_response,
        "http_client": http_client,
        "jwt_header": header_b64,
        "jwt_payload": payload_b64,
        "jwt_token": jwt_token,
        "jwt_parser": jwt_parser,
        "ca_pk": ca_pk,
        "server_kem_sk": server_kem_sk,
        "cert": cert,
    }


def _run_protocol_handshake(materials: Dict[str, Any]) -> None:
    client = ClientHandshake(
        expected_identity="auth-server",
        ca_pk=materials["ca_pk"],
        mode="baseline",
    )
    server = ServerHandshake(
        server_identity="auth-server",
        server_lt_sk=materials["server_kem_sk"],
        cert=materials["cert"],
    )

    client_hello = client.client_hello()
    server_hello = server.process_client_hello(client_hello)
    client_key_exchange, session = client.process_server_hello(server_hello)
    server_finished = server.process_client_key_exchange(client_key_exchange)
    client.process_server_finished(server_finished, session)
    client_finished = client.client_finished()
    server.verify_client_finished(client_finished)


def _reload_hot_modules() -> None:
    """Ensure mode flips apply to already-imported modules in benchmark process."""
    module_names = [
        "utils.serialization",
        "crypto.key_schedule",
        "kemtls._http_bridge",
        "client.kemtls_http_client",
        "oidc.jwt_handler",
        "kemtls.handshake",
    ]
    for name in module_names:
        if name in sys.modules:
            importlib.reload(sys.modules[name])


def _build_operations(materials: Dict[str, Any]) -> Dict[str, Tuple[str, Callable[[], Any], int, int]]:
    return {
        "serialization_roundtrip": (
            "micro",
            lambda: deserialize_message(serialize_message(materials["serialization_payload"])),
            50,
            500,
        ),
        "key_schedule_hkdf_extract": (
            "micro",
            lambda: hkdf_extract(b"salt-for-bench", b"input-key-material-bench"),
            50,
            500,
        ),
        "hashing_transcript_hash": (
            "micro",
            lambda: compute_transcript_hash(materials["transcript_chunks"]),
            50,
            500,
        ),
        "key_schedule_hkdf_expand_label": (
            "micro",
            lambda: hkdf_expand_label(b"s" * 32, b"traffic", b"ctx", 32),
            50,
            500,
        ),
        "http_parse_request": (
            "micro",
            lambda: parse_http_request(materials["http_request"]),
            50,
            500,
        ),
        "http_parse_response": (
            "micro",
            lambda: materials["http_client"]._parse_response(materials["http_response"]),
            50,
            500,
        ),
        "jwt_helper_split": (
            "micro",
            lambda: rust_jwt.split_jwt(
                materials["jwt_token"],
                fallback=lambda token: tuple(token.split(".", 2)),
            ),
            50,
            500,
        ),
        "jwt_helper_signing_input": (
            "micro",
            lambda: rust_jwt.jwt_signing_input(
                materials["jwt_header"],
                materials["jwt_payload"],
                fallback=lambda h, p: f"{h}.{p}".encode("ascii"),
            ),
            50,
            500,
        ),
        "jwt_extract_confirmation_claim": (
            "micro",
            lambda: materials["jwt_parser"].extract_confirmation_claim(materials["jwt_token"]),
            50,
            500,
        ),
        "protocol_handshake_baseline": (
            "flow",
            lambda: _run_protocol_handshake(materials),
            5,
            40,
        ),
    }


def _build_batched_operations(
    materials: Dict[str, Any],
) -> Dict[str, Tuple[str, Callable[[], Any], int, int, int]]:
    return {
        "serialization_roundtrip_batched": (
            "macro",
            lambda: deserialize_message(serialize_message(materials["serialization_payload"])),
            20,
            120,
            256,
        ),
        "key_schedule_hkdf_extract_batched": (
            "macro",
            lambda: hkdf_extract(b"salt-for-bench", b"input-key-material-bench"),
            20,
            120,
            512,
        ),
        "hashing_transcript_hash_batched": (
            "macro",
            lambda: compute_transcript_hash(materials["transcript_chunks"]),
            20,
            120,
            1024,
        ),
        "http_parse_response_batched": (
            "macro",
            lambda: materials["http_client"]._parse_response(materials["http_response"]),
            20,
            120,
            256,
        ),
        "jwt_helper_signing_input_batched": (
            "macro",
            lambda: rust_jwt.jwt_signing_input(
                materials["jwt_header"],
                materials["jwt_payload"],
                fallback=lambda h, p: f"{h}.{p}".encode("ascii"),
            ),
            20,
            120,
            1024,
        ),
    }


def _run_mode(mode: str, operations: Dict[str, Tuple[str, Callable[[], Any], int, int]], *, repeat_override: int | None, warmup_override: int | None) -> Dict[str, Any]:
    mode_results: Dict[str, Any] = {}
    for name, (scope, fn, default_warmup, default_repeat) in operations.items():
        warmup = warmup_override if warmup_override is not None else default_warmup
        repeat = repeat_override if repeat_override is not None else default_repeat
        mode_results[name] = {
            "scope": scope,
            **_measure(fn, warmup=warmup, repeat=repeat),
        }
    return mode_results


def _run_mode_batched(
    mode: str,
    operations: Dict[str, Tuple[str, Callable[[], Any], int, int, int]],
    *,
    repeat_override: int | None,
    warmup_override: int | None,
) -> Dict[str, Any]:
    mode_results: Dict[str, Any] = {}
    for name, (scope, fn, default_warmup, default_repeat, inner_loops) in operations.items():
        warmup = warmup_override if warmup_override is not None else default_warmup
        repeat = repeat_override if repeat_override is not None else default_repeat
        mode_results[name] = {
            "scope": scope,
            **_measure_batched(fn, inner_loops=inner_loops, warmup=warmup, repeat=repeat),
        }
    return mode_results


def _build_comparison(rust_results: Dict[str, Any], python_results: Dict[str, Any]) -> Dict[str, Any]:
    comparison: Dict[str, Any] = {}
    for name in rust_results:
        rust_avg = rust_results[name]["stats"]["avg_us"]
        py_avg = python_results[name]["stats"]["avg_us"]
        speedup = py_avg / rust_avg if rust_avg > 0 else 0.0
        delta_pct = ((py_avg - rust_avg) / py_avg * 100.0) if py_avg > 0 else 0.0
        comparison[name] = {
            "scope": rust_results[name]["scope"],
            "rust_avg_us": round(rust_avg, 3),
            "python_avg_us": round(py_avg, 3),
            "speedup_x": round(speedup, 3),
            "rust_faster_by_percent": round(delta_pct, 2),
        }
    return comparison


def _write_csv(csv_path: Path, comparison: Dict[str, Any]) -> None:
    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "benchmark",
                "scope",
                "rust_avg_us",
                "python_avg_us",
                "speedup_x",
                "rust_faster_by_percent",
            ],
        )
        writer.writeheader()
        for benchmark, row in comparison.items():
            writer.writerow({"benchmark": benchmark, **row})


def _print_summary(comparison: Dict[str, Any]) -> None:
    print("\nRust vs Python fallback summary (avg latency)")
    print("-" * 82)
    print(f"{'benchmark':36} {'scope':8} {'rust(us)':>10} {'python(us)':>12} {'speedup':>10}")
    print("-" * 82)
    for benchmark, row in comparison.items():
        print(
            f"{benchmark:36} {row['scope']:8} {row['rust_avg_us']:10.3f} {row['python_avg_us']:12.3f} {row['speedup_x']:10.3f}"
        )


def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or f"rustcmp-{uuid.uuid4().hex[:8]}")
    repeat_override = config.get("repeat")
    warmup_override = config.get("warmup")
    environment_profile = str(config.get("environment_profile", "local"))

    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    json_path = raw_dir / "rust_fallback_compare.json"
    csv_path = raw_dir / "rust_fallback_compare.csv"

    materials = _build_test_materials()
    operations = _build_operations(materials)
    batched_operations = _build_batched_operations(materials)

    with _rust_backend_mode(enabled=True):
        _reload_hot_modules()
        rust_results = _run_mode(
            "rust_enabled",
            operations,
            repeat_override=repeat_override,
            warmup_override=warmup_override,
        )
        rust_batched_results = _run_mode_batched(
            "rust_enabled",
            batched_operations,
            repeat_override=repeat_override,
            warmup_override=warmup_override,
        )

    with _rust_backend_mode(enabled=False):
        _reload_hot_modules()
        python_results = _run_mode(
            "python_fallback",
            operations,
            repeat_override=repeat_override,
            warmup_override=warmup_override,
        )
        python_batched_results = _run_mode_batched(
            "python_fallback",
            batched_operations,
            repeat_override=repeat_override,
            warmup_override=warmup_override,
        )

    comparison = _build_comparison(rust_results, python_results)
    batched_comparison = _build_comparison(rust_batched_results, python_batched_results)

    payload = {
        "run_id": run_id,
        "environment_profile": environment_profile,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "methodology": {
            "design": "same-process A/B with Rust enabled vs forced Python fallback",
            "scope_note": "Partial-path benchmark. Measures helper and handshake paths, not full distributed system throughput.",
            "build_profile": get_build_profile(),
            "synthetic_vs_meaningful_review": {
                "synthetic": [
                    "serialization_roundtrip",
                    "key_schedule_hkdf_extract",
                    "hashing_transcript_hash",
                    "key_schedule_hkdf_expand_label",
                    "http_parse_request",
                    "http_parse_response",
                    "jwt_helper_split",
                    "jwt_helper_signing_input",
                ],
                "meaningful": [
                    "jwt_extract_confirmation_claim",
                    "protocol_handshake_baseline",
                ],
            },
        },
        "rust_enabled": rust_results,
        "python_fallback": python_results,
        "comparison": comparison,
        "rust_enabled_batched": rust_batched_results,
        "python_fallback_batched": python_batched_results,
        "comparison_batched": batched_comparison,
    }

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _write_csv(csv_path, comparison)
    _print_summary(comparison)

    print("\nAmortized (batched) comparison summary (avg latency)")
    _print_summary(batched_comparison)

    print(f"\n[*] Wrote comparison JSON: {json_path}")
    print(f"[*] Wrote comparison CSV:  {csv_path}")
    return json_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Rust enabled vs Python fallback benchmark comparison")
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repeat", type=int, default=None, help="Override repeat for all benchmarks")
    parser.add_argument("--warmup", type=int, default=None, help="Override warmup for all benchmarks")
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
    main()
