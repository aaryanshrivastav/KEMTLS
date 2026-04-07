from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import statistics
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from kemtls.handshake import ClientHandshake, ServerHandshake
from kemtls.pdk import PDKTrustStore
from oidc.auth_endpoints import InMemoryClientRegistry
from servers.auth_server_app import create_auth_server_app
from servers.resource_server_app import create_resource_server_app
from telemetry.collector import KEMTLSHandshakeCollector, OIDCTokenCollector, OIDCUserinfoCollector
from utils.encoding import base64url_decode, base64url_encode
from utils.helpers import generate_random_string


def _load_keys() -> Dict[str, Any]:
    base_dir = ROOT_DIR / "keys"
    with (base_dir / "ca" / "ca_keys.json").open("r", encoding="utf-8") as file_handle:
        ca_config = json.load(file_handle)
    with (base_dir / "auth_server" / "as_config.json").open("r", encoding="utf-8") as file_handle:
        as_config = json.load(file_handle)
    with (base_dir / "resource_server" / "rs_config.json").open("r", encoding="utf-8") as file_handle:
        rs_config = json.load(file_handle)
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
        "auth_jwt_pk": base64url_decode(as_config["jwt_signing_pk"]),
        "auth_jwt_sk": base64url_decode(as_config["jwt_signing_sk"]),
        "auth_sk": base64url_decode(as_config["longterm_sk"]),
        "auth_cert": as_config["certificate"],
        "auth_pdk_key_id": as_config.get("pdk_key_id", "as-key-1"),
        "resource_jwt_aud": "client123",
        "resource_sk": base64url_decode(rs_config["longterm_sk"]),
        "resource_cert": rs_config["certificate"],
        "pdk_store": pdk_store,
    }


def _challenge(verifier: str) -> str:
    return base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _build_apps(keys: Dict[str, Any]):
    issuer_url = "https://issuer.example"
    client_config = {
        "client123": {"redirect_uris": ["https://client.example/cb"]},
    }
    auth_app = create_auth_server_app(
        {
            "issuer": issuer_url,
            "issuer_public_key": keys["auth_jwt_pk"],
            "issuer_secret_key": keys["auth_jwt_sk"],
            "clients": client_config,
            "demo_user": "alice",
            "introspection_endpoint": f"{issuer_url}/introspect",
            "kemtls_modes_supported": ["baseline", "pdk", "auto"],
        },
        stores={"client_registry": InMemoryClientRegistry(client_config)},
    )
    resource_app = create_resource_server_app(
        {
            "issuer": issuer_url,
            "issuer_public_key": keys["auth_jwt_pk"],
            "resource_audience": keys["resource_jwt_aud"],
        }
    )
    return auth_app, resource_app


def _build_session(mode: str, keys: Dict[str, Any]):
    server_identity = "auth-server"
    server_collector = KEMTLSHandshakeCollector()
    client_collector = KEMTLSHandshakeCollector()

    client = ClientHandshake(
        expected_identity=server_identity,
        ca_pk=keys["ca_pk"],
        pdk_store=keys["pdk_store"],
        mode=mode,
        collector=client_collector,
    )
    server = ServerHandshake(
        server_identity=server_identity,
        server_lt_sk=keys["auth_sk"],
        cert=keys["auth_cert"],
        pdk_key_id=keys["auth_pdk_key_id"],
        collector=server_collector,
    )

    client_collector.start_hct()
    server_collector.start_hct()
    client_hello = client.client_hello()
    server_hello = server.process_client_hello(client_hello)
    client_key_exchange, client_session = client.process_server_hello(server_hello)
    server_finished = server.process_client_key_exchange(client_key_exchange)
    session = client.process_server_finished(server_finished, client_session)
    server.verify_client_finished(client.client_finished())
    client_collector.end_hct()
    server_collector.end_hct()

    return session, client_collector.get_metrics()


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * p)))
    return float(ordered[idx])


def _single_request(mode: str, keys: Dict[str, Any]) -> Dict[str, Any]:
    start_ns = time.perf_counter_ns()
    try:
        auth_app, resource_app = _build_apps(keys)
        auth_endpoint = auth_app.extensions["auth_endpoint"]
        token_endpoint = auth_app.extensions["token_endpoint"]
        userinfo_endpoint = resource_app.extensions["userinfo_endpoint"]

        session, handshake_metrics = _build_session(mode, keys)
        verifier = generate_random_string(64)
        authorize_result = auth_endpoint.handle_authorize_request(
            client_id="client123",
            redirect_uri="https://client.example/cb",
            scope="openid profile email",
            state=generate_random_string(16),
            nonce=generate_random_string(16),
            user_id="alice",
            response_type="code",
            code_challenge=_challenge(verifier),
            code_challenge_method="S256",
        )
        if "code" not in authorize_result:
            raise ValueError("authorize_error")

        token_collector = OIDCTokenCollector()
        token_collector.grant_type = "authorization_code"
        token_result = token_endpoint.handle_token_request(
            grant_type="authorization_code",
            client_id="client123",
            redirect_uri="https://client.example/cb",
            code=authorize_result["code"],
            code_verifier=verifier,
            session=session,
            collector=token_collector,
        )
        if "access_token" not in token_result:
            raise ValueError("token_error")

        userinfo_collector = OIDCUserinfoCollector()
        userinfo_result, userinfo_status = userinfo_endpoint.handle_userinfo_request(
            token_result["access_token"],
            session=session,
            collector=userinfo_collector,
        )
        if userinfo_status != 200:
            raise ValueError(f"userinfo_error:{userinfo_result}")

        refresh_collector = OIDCTokenCollector()
        refresh_collector.grant_type = "refresh_token"
        refresh_result = token_endpoint.handle_token_request(
            grant_type="refresh_token",
            client_id="client123",
            refresh_token=token_result["refresh_token"],
            session=session,
            collector=refresh_collector,
        )
        if "access_token" not in refresh_result:
            raise ValueError("refresh_error")

        end_ns = time.perf_counter_ns()
        latency_ms = (end_ns - start_ns) / 1_000_000
        return {
            "ok": True,
            "latency_ms": latency_ms,
            "t_auth_total_ms": latency_ms,
            "t_token_ms": token_collector.get_metrics()["t_total_ns"] / 1_000_000,
            "t_userinfo_ms": userinfo_collector.get_metrics()["t_total_ns"] / 1_000_000,
            "t_tls_hs_ms": float(handshake_metrics["hct_ms"]),
            "error_type": "",
        }
    except Exception as exc:
        end_ns = time.perf_counter_ns()
        return {
            "ok": False,
            "latency_ms": (end_ns - start_ns) / 1_000_000,
            "t_auth_total_ms": 0.0,
            "t_token_ms": 0.0,
            "t_userinfo_ms": 0.0,
            "t_tls_hs_ms": 0.0,
            "error_type": exc.__class__.__name__,
        }


def _run_level(mode: str, keys: Dict[str, Any], total_requests: int, concurrency: int) -> Dict[str, Any]:
    started = time.perf_counter()
    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_single_request, mode, keys) for _ in range(total_requests)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    duration = max(time.perf_counter() - started, 1e-9)

    successes = [entry for entry in results if entry["ok"]]
    failures = [entry for entry in results if not entry["ok"]]
    latencies = [float(entry["latency_ms"]) for entry in successes]
    error_counter = Counter(entry["error_type"] for entry in failures)

    def _mean(field: str) -> float:
        if not successes:
            return 0.0
        return statistics.mean(float(entry[field]) for entry in successes)

    success_count = len(successes)
    failure_count = len(failures)
    error_rate = (failure_count / total_requests) * 100.0 if total_requests else 0.0

    return {
        "mode": mode,
        "concurrency": concurrency,
        "total_requests": total_requests,
        "successes": success_count,
        "failures": failure_count,
        "error_rate_pct": error_rate,
        "throughput_req_sec": total_requests / duration,
        "avg_latency_ms": statistics.mean(latencies) if latencies else 0.0,
        "p50_latency_ms": _percentile(latencies, 0.50),
        "p95_latency_ms": _percentile(latencies, 0.95),
        "p99_latency_ms": _percentile(latencies, 0.99),
        "min_latency_ms": min(latencies) if latencies else 0.0,
        "max_latency_ms": max(latencies) if latencies else 0.0,
        "t_auth_total_ms_avg": _mean("t_auth_total_ms"),
        "t_token_ms_avg": _mean("t_token_ms"),
        "t_userinfo_ms_avg": _mean("t_userinfo_ms"),
        "t_tls_hs_ms_avg": _mean("t_tls_hs_ms"),
        "errors": dict(error_counter),
    }


def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    repeat = int(config.get("repeat", 1000))
    warmup = int(config.get("warmup", 50))
    concurrency_levels = [int(v) for v in config.get("load_concurrency_levels", [1, 5, 10, 25, 50, 100])]
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw_dir / "load_results.csv"
    summary_path = raw_dir / "load_summary.json"
    keys = _load_keys()

    print("Running load benchmark suite...")
    print(f"[*] run_id={run_id}")
    print(f"[*] environment_profile={environment_profile}")
    print(f"[*] warmup_requests={warmup} measured_requests={repeat}")

    rows: List[Dict[str, Any]] = []
    summaries: Dict[str, Dict[str, Any]] = {"baseline": {}, "pdk": {}}

    for mode in ("baseline", "pdk"):
        for concurrency in concurrency_levels:
            print(f"[*] {mode}: concurrency={concurrency} warmup")
            if warmup > 0:
                _run_level(mode, keys, warmup, concurrency)

            print(f"[*] {mode}: concurrency={concurrency} measured")
            result = _run_level(mode, keys, repeat, concurrency)
            row = {
                "run_id": run_id,
                "protocol": "OIDC_LOAD",
                "scenario": mode,
                "concurrency": concurrency,
                "total_requests": result["total_requests"],
                "successes": result["successes"],
                "failures": result["failures"],
                "error_rate_pct": round(float(result["error_rate_pct"]), 3),
                "throughput_req_sec": round(float(result["throughput_req_sec"]), 3),
                "avg_latency_ms": round(float(result["avg_latency_ms"]), 3),
                "p50_latency_ms": round(float(result["p50_latency_ms"]), 3),
                "p95_latency_ms": round(float(result["p95_latency_ms"]), 3),
                "p99_latency_ms": round(float(result["p99_latency_ms"]), 3),
                "min_latency_ms": round(float(result["min_latency_ms"]), 3),
                "max_latency_ms": round(float(result["max_latency_ms"]), 3),
                "t_auth_total_ms_avg": round(float(result["t_auth_total_ms_avg"]), 3),
                "t_token_ms_avg": round(float(result["t_token_ms_avg"]), 3),
                "t_userinfo_ms_avg": round(float(result["t_userinfo_ms_avg"]), 3),
                "t_tls_hs_ms_avg": round(float(result["t_tls_hs_ms_avg"]), 3),
                "warmup_requests": warmup,
                "environment_profile": environment_profile,
            }
            rows.append(row)
            summaries[mode][str(concurrency)] = {
                **row,
                "errors": result["errors"],
            }

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "run_id",
                "protocol",
                "scenario",
                "concurrency",
                "total_requests",
                "successes",
                "failures",
                "error_rate_pct",
                "throughput_req_sec",
                "avg_latency_ms",
                "p50_latency_ms",
                "p95_latency_ms",
                "p99_latency_ms",
                "min_latency_ms",
                "max_latency_ms",
                "t_auth_total_ms_avg",
                "t_token_ms_avg",
                "t_userinfo_ms_avg",
                "t_tls_hs_ms_avg",
                "warmup_requests",
                "environment_profile",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(f"[*] Load benchmarks saved to {csv_path}")
    print(f"[*] Load summary saved to {summary_path}")
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real OIDC/KEMTLS load benchmarks")
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
