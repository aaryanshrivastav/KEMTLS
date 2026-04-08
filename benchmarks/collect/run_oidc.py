from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from client.kemtls_http_client import KEMTLSHttpClient
from client.oidc_client import OIDCClient
from telemetry.collector import KEMTLSHandshakeCollector

from runtime_support import (
    BENCH_CLIENT_ID,
    BENCH_REDIRECT_URI,
    BENCH_SCOPE,
    BenchmarkStack,
)


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "avg": statistics.mean(values),
        "median": statistics.median(values),
        "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
    }


def _protocol_modes(protocols: Iterable[str]) -> List[str]:
    normalized = {str(item).lower() for item in protocols}
    modes: List[str] = []
    if "kemtls" in normalized or "baseline" in normalized:
        modes.append("baseline")
    if "kemtls_pdk" in normalized or "pdk" in normalized:
        modes.append("pdk")
    return modes or ["baseline", "pdk"]


def _build_http_client(stack: BenchmarkStack, *, expected_identity: str, mode: str, keep_alive: bool) -> KEMTLSHttpClient:
    return KEMTLSHttpClient(
        ca_pk=stack.keys["ca_pk"],
        pdk_store=stack.keys["pdk_store"],
        expected_identity=expected_identity,
        mode=mode,
        transport="tcp",
        keep_alive=keep_alive,
    )


def _run_flow(mode: str, stack: BenchmarkStack) -> Dict[str, Any]:
    auth_url = stack.auth_url
    resource_url = stack.resource_url

    auth_http = _build_http_client(stack, expected_identity="auth-server", mode=mode, keep_alive=True)
    auth_http.client.collector = KEMTLSHandshakeCollector()
    oidc_client = OIDCClient(
        http_client=auth_http,
        client_id=BENCH_CLIENT_ID,
        issuer_url=auth_url,
        redirect_uri=BENCH_REDIRECT_URI,
    )

    discovery_start = time.perf_counter_ns()
    discovery_resp = auth_http.get(f"{auth_url}/.well-known/openid-configuration")
    t_discovery_ms = (time.perf_counter_ns() - discovery_start) / 1_000_000
    auth_handshake_ms = float(auth_http.client.collector.get_metrics()["hct_ms"]) if auth_http.client.collector else 0.0
    discovery_request_bytes = int(discovery_resp["kemtls_metadata"]["request_bytes"])
    discovery_response_bytes = int(discovery_resp["kemtls_metadata"]["response_bytes"])

    authorize_url = oidc_client.start_auth(scope=BENCH_SCOPE)
    authorize_start = time.perf_counter_ns()
    authorize_resp = auth_http.get(authorize_url)
    t_authorize_ms = (time.perf_counter_ns() - authorize_start) / 1_000_000
    authorization_code = authorize_resp.get("body", {}).get("code")
    if authorize_resp.get("status") != 200 or not authorization_code:
        raise ValueError(f"authorize failed: {authorize_resp}")

    token_start = time.perf_counter_ns()
    token_result = oidc_client.exchange_code(authorization_code)
    t_token_ms = (time.perf_counter_ns() - token_start) / 1_000_000
    access_token = token_result.get("access_token")
    refresh_token = token_result.get("refresh_token")
    if not access_token or not refresh_token:
        raise ValueError(f"token exchange failed: {token_result}")

    token_telemetry = token_result.get("_telemetry", {})
    binding_keypair = auth_http.get_binding_keypair()

    resource_http = _build_http_client(stack, expected_identity="resource-server", mode=mode, keep_alive=False)
    resource_http.client.collector = KEMTLSHandshakeCollector()
    resource_http.set_binding_keypair(*binding_keypair)
    userinfo_start = time.perf_counter_ns()
    userinfo_resp = resource_http.get(
        f"{resource_url}/benchmark/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    t_userinfo_ms = (time.perf_counter_ns() - userinfo_start) / 1_000_000
    if userinfo_resp.get("status") != 200:
        raise ValueError(f"userinfo failed: {userinfo_resp}")
    userinfo_telemetry = userinfo_resp.get("body", {}).get("_telemetry", {})
    resource_handshake_ms = float(resource_http.client.collector.get_metrics()["hct_ms"]) if resource_http.client.collector else 0.0

    refresh_start = time.perf_counter_ns()
    refreshed = oidc_client.refresh()
    t_refresh_ms = (time.perf_counter_ns() - refresh_start) / 1_000_000
    if "access_token" not in refreshed:
        raise ValueError(f"refresh failed: {refreshed}")
    refresh_telemetry = refreshed.get("_telemetry", {})

    replay_http = _build_http_client(stack, expected_identity="resource-server", mode=mode, keep_alive=False)
    replay_resp = replay_http.get(
        f"{resource_url}/benchmark/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    replay_blocked = replay_resp.get("status") in {401, 403}
    replay_http.close()

    stale_refresh_token = refresh_token
    stale_refresh_start = time.perf_counter_ns()
    stale_refresh_resp = auth_http.post(
        f"{auth_url}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": stale_refresh_token,
            "client_id": BENCH_CLIENT_ID,
        },
    )
    stale_refresh_ms = (time.perf_counter_ns() - stale_refresh_start) / 1_000_000
    stale_refresh_rejected = stale_refresh_resp.get("status") == 400

    total_request_bytes = sum(
        (
            discovery_request_bytes,
            int(authorize_resp["kemtls_metadata"]["request_bytes"]),
            int(token_result.get("_http_request_bytes", 0) or 0),
            int(userinfo_resp["kemtls_metadata"]["request_bytes"]),
            int(refreshed.get("_http_request_bytes", 0) or 0),
        )
    )
    total_response_bytes = sum(
        (
            discovery_response_bytes,
            int(authorize_resp["kemtls_metadata"]["response_bytes"]),
            int(token_result.get("_http_response_bytes", 0) or 0),
            int(userinfo_resp["kemtls_metadata"]["response_bytes"]),
            int(refreshed.get("_http_response_bytes", 0) or 0),
        )
    )

    auth_http.close()
    resource_http.close()

    t_login_to_resource_ms = t_discovery_ms + t_authorize_ms + t_token_ms + t_userinfo_ms
    t_full_cycle_ms = t_login_to_resource_ms + t_refresh_ms
    t_auth_total_ms = t_authorize_ms + t_token_ms
    tls_hs_ms = auth_handshake_ms + resource_handshake_ms
    s_id_token = str(token_result.get("id_token", ""))
    s_access_token = str(access_token)

    return {
        "mode": mode,
        "t_discovery_ms": t_discovery_ms,
        "t_authorize_ms": t_authorize_ms,
        "t_token_ms": t_token_ms,
        "t_userinfo_ms": t_userinfo_ms,
        "t_refresh_ms": t_refresh_ms,
        "t_auth_total_ms": t_auth_total_ms,
        "t_full_cycle_ms": t_full_cycle_ms,
        "t_login_to_resource_ms": t_login_to_resource_ms,
        "t_tls_hs_ms": tls_hs_ms,
        "t_jwt_sign_ms": float(token_telemetry.get("t_jwt_sign_ms", 0.0)),
        "t_jwt_verify_ms": float(userinfo_telemetry.get("t_verify_ms", 0.0)),
        "t_binding_verify_ms": float(userinfo_telemetry.get("t_binding_verify_ms", 0.0)),
        "s_id_token_bytes": len(s_id_token),
        "s_id_token_header": int(token_telemetry.get("token_sizes", {}).get("header", 0)),
        "s_id_token_payload": int(token_telemetry.get("token_sizes", {}).get("payload", 0)),
        "s_id_token_sig": int(token_telemetry.get("token_sizes", {}).get("signature", 0)),
        "s_access_token_bytes": len(s_access_token),
        "s_refresh_token_bytes": len(str(refresh_token)),
        "s_total_request_bytes": total_request_bytes,
        "s_total_response_bytes": total_response_bytes,
        "handshake_mode": mode,
        "replay_blocked": replay_blocked,
        "stale_refresh_rejected": stale_refresh_rejected,
        "stale_refresh_ms": stale_refresh_ms,
    }

def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    scenario = str((config.get("scenarios") or ["loopback"])[0])
    warmup = int(config.get("warmup", 50))
    repeat = int(config.get("repeat", 1000))
    protocols = list(config.get("protocols", ["kemtls", "kemtls_pdk"]))
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw_dir / "oidc_results.csv"
    summary_path = raw_dir / "oidc_summary.json"

    print("Running OIDC benchmark suite...")
    print(f"[*] run_id={run_id}")
    print(f"[*] environment_profile={environment_profile}")
    print(f"[*] scenario={scenario}")
    print(f"[*] warmup={warmup} repeat={repeat}")

    rows: List[Dict[str, Any]] = []
    summaries: Dict[str, Dict[str, Any]] = {}
    negative_cases: Dict[str, Dict[str, int]] = {}

    with BenchmarkStack(transport="tcp") as stack:
        stack.start_oidc_servers()
        modes = _protocol_modes(protocols)
        for mode in modes:
            for _ in range(warmup):
                _run_flow(mode, stack)

            t_auth_total_values: List[float] = []
            t_token_values: List[float] = []
            t_userinfo_values: List[float] = []
            replay_blocked_count = 0
            stale_refresh_rejected_count = 0

            for iteration in range(repeat):
                result = _run_flow(mode, stack)
                t_auth_total_values.append(float(result["t_auth_total_ms"]))
                t_token_values.append(float(result["t_token_ms"]))
                t_userinfo_values.append(float(result["t_userinfo_ms"]))
                replay_blocked_count += int(bool(result["replay_blocked"]))
                stale_refresh_rejected_count += int(bool(result["stale_refresh_rejected"]))

                rows.append(
                    {
                        "run_id": run_id,
                        "protocol": "OIDC",
                        "scenario": scenario,
                        "handshake_mode": mode,
                        "t_discovery_ms": round(float(result["t_discovery_ms"]), 3),
                        "t_authorize_ms": round(float(result["t_authorize_ms"]), 3),
                        "t_token_ms": round(float(result["t_token_ms"]), 3),
                        "t_userinfo_ms": round(float(result["t_userinfo_ms"]), 3),
                        "t_refresh_ms": round(float(result["t_refresh_ms"]), 3),
                        "t_auth_total_ms": round(float(result["t_auth_total_ms"]), 3),
                        "t_full_cycle_ms": round(float(result["t_full_cycle_ms"]), 3),
                        "t_login_to_resource_ms": round(float(result["t_login_to_resource_ms"]), 3),
                        "t_tls_hs_ms": round(float(result["t_tls_hs_ms"]), 3),
                        "t_jwt_sign_ms": round(float(result["t_jwt_sign_ms"]), 3),
                        "t_jwt_verify_ms": round(float(result["t_jwt_verify_ms"]), 3),
                        "t_binding_verify_ms": round(float(result["t_binding_verify_ms"]), 3),
                        "s_id_token_bytes": int(result["s_id_token_bytes"]),
                        "s_id_token_header": int(result["s_id_token_header"]),
                        "s_id_token_payload": int(result["s_id_token_payload"]),
                        "s_id_token_sig": int(result["s_id_token_sig"]),
                        "s_access_token_bytes": int(result["s_access_token_bytes"]),
                        "s_refresh_token_bytes": int(result["s_refresh_token_bytes"]),
                        "s_total_request_bytes": int(result["s_total_request_bytes"]),
                        "s_total_response_bytes": int(result["s_total_response_bytes"]),
                        "replay_blocked": int(bool(result["replay_blocked"])),
                        "stale_refresh_rejected": int(bool(result["stale_refresh_rejected"])),
                        "iteration": iteration,
                        "environment_profile": environment_profile,
                    }
                )

            summaries[mode] = {
                "t_auth_total": _stats(t_auth_total_values),
                "t_token": _stats(t_token_values),
                "t_userinfo": _stats(t_userinfo_values),
            }
            negative_cases[mode] = {
                "replay_blocked": replay_blocked_count,
                "stale_refresh_rejected": stale_refresh_rejected_count,
                "iterations": repeat,
            }

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "run_id",
                "protocol",
                "scenario",
                "handshake_mode",
                "t_discovery_ms",
                "t_authorize_ms",
                "t_token_ms",
                "t_userinfo_ms",
                "t_refresh_ms",
                "t_auth_total_ms",
                "t_full_cycle_ms",
                "t_login_to_resource_ms",
                "t_tls_hs_ms",
                "t_jwt_sign_ms",
                "t_jwt_verify_ms",
                "t_binding_verify_ms",
                "s_id_token_bytes",
                "s_id_token_header",
                "s_id_token_payload",
                "s_id_token_sig",
                "s_access_token_bytes",
                "s_refresh_token_bytes",
                "s_total_request_bytes",
                "s_total_response_bytes",
                "replay_blocked",
                "stale_refresh_rejected",
                "iteration",
                "environment_profile",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(
        json.dumps({"summaries": summaries, "negative_cases": negative_cases}, indent=2),
        encoding="utf-8",
    )
    print(f"[*] OIDC benchmarks saved to {csv_path}")
    print(f"[*] OIDC summary saved to {summary_path}")
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real socket-backed OIDC benchmarks")
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
