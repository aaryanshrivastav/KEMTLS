from __future__ import annotations

import argparse
import csv
import json
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

from client.kemtls_http_client import KEMTLSHttpClient
from client.oidc_client import OIDCClient
from runtime_support import (
    BENCH_CLIENT_ID,
    BENCH_REDIRECT_URI,
    BENCH_SCOPE,
    BenchmarkStack,
)

# Import collectors for sizing and timers
from telemetry.collector import OIDCTokenCollector, OIDCUserinfoCollector

def _run_flow(mode: str, stack: BenchmarkStack) -> Dict[str, Any]:
    # Measurements
    t_handshake_ms = 0.0
    t_authorize_ms = 0.0
    t_token_ms = 0.0
    t_userinfo_ms = 0.0
    t_refresh_ms = 0.0
    
    # 1. Handshake & Discovery
    t0 = time.perf_counter_ns()
    auth_http = KEMTLSHttpClient(
        ca_pk=stack.keys["ca_pk"],
        pdk_store=stack.keys["pdk_store"],
        expected_identity="auth-server",
        mode=mode,
        keep_alive=True,
    )
    # The first request triggers handshake
    auth_http.get(f"{stack.auth_url}/.well-known/openid-configuration")
    t_handshake_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    
    oidc_client = OIDCClient(
        http_client=auth_http,
        client_id=BENCH_CLIENT_ID,
        issuer_url=stack.auth_url,
        redirect_uri=BENCH_REDIRECT_URI,
    )

    # 2. Authorize
    t0 = time.perf_counter_ns()
    auth_url = oidc_client.start_auth(scope=BENCH_SCOPE)
    authorize_resp = auth_http.get(auth_url)
    t_authorize_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    
    code = authorize_resp["body"]["code"]

    # 3. Token
    t0 = time.perf_counter_ns()
    token_result = oidc_client.exchange_code(code)
    t_token_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    
    token = token_result["access_token"]
    token_telemetry = token_result.get("_telemetry", {})

    # 4. Resource / Userinfo
    resource_http = KEMTLSHttpClient(
        ca_pk=stack.keys["ca_pk"],
        pdk_store=stack.keys["pdk_store"],
        expected_identity="resource-server",
        mode=mode,
    )
    resource_http.set_binding_keypair(*auth_http.get_binding_keypair())
    
    t0 = time.perf_counter_ns()
    userinfo_resp = resource_http.get(
        f"{stack.resource_url}/benchmark/userinfo",
        headers={"Authorization": f"Bearer {token}"},
    )
    t_userinfo_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    
    userinfo_body = userinfo_resp["body"]
    userinfo_telemetry = userinfo_body.get("_telemetry", {})

    # 5. Refresh
    t0 = time.perf_counter_ns()
    oidc_client.refresh()
    t_refresh_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

    # 6. Replay Test (Attempt same token again, should fail if replay detection is on)
    replay_blocked = 0
    replay_resp = resource_http.get(
        f"{stack.resource_url}/benchmark/userinfo",
        headers={"Authorization": f"Bearer {token}"},
    )
    # The server should reject the second use of the same token/nonce for PoP
    if replay_resp.get("status") != 200:
        replay_blocked = 1

    auth_http.close()
    resource_http.close()

    total_auth_ms = t_authorize_ms + t_token_ms
    full_cycle_ms = t_handshake_ms + t_authorize_ms + t_token_ms + t_userinfo_ms + t_refresh_ms

    return {
        "auth_total_ms": total_auth_ms,
        "full_cycle_ms": full_cycle_ms,
        "t_handshake_ms": t_handshake_ms,
        "t_authorize_ms": t_authorize_ms,
        "t_token_ms": t_token_ms,
        "t_userinfo_ms": t_userinfo_ms,
        "t_refresh_ms": t_refresh_ms,
        "t_jwt_sign_ms": float(token_telemetry.get("t_jwt_sign_ms", 0.0)),
        "t_jwt_verify_ms": float(userinfo_telemetry.get("t_verify_ms", 0.0)),
        "t_pop_verify_ms": float(userinfo_telemetry.get("t_binding_verify_ms", 0.0)),
        "replay_blocked": replay_blocked,
        "bytes_id_token": int(token_telemetry.get("token_sizes", {}).get("id_token", 0)),
    }

def run_benchmark(config: Dict[str, Any]):
    run_id = config.get("run_id") or uuid.uuid4().hex[:8]
    repeat = config.get("repeat", 10)
    warmup = config.get("warmup", 2)
    protocols = config.get("protocols", ["baseline", "pdk"])
    
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    csv_path = raw_dir / "oidc.csv"
    
    print("Running layer B OIDC benchmarks...")
    
    rows = []
    with BenchmarkStack(transport="tcp") as stack:
        stack.start_oidc_servers()
        
        for mode in protocols:
            print(f"[*] OIDC -> Mode: {mode}")
            for _ in range(warmup):
                _run_flow(mode, stack)
                
            for i in range(repeat):
                res = _run_flow(mode, stack)
                rows.append({
                    "run_id": run_id,
                    "protocol": "KEMTLS",
                    "scenario": mode,
                    "auth_total_ms": round(res["auth_total_ms"], 3),
                    "full_cycle_ms": round(res["full_cycle_ms"], 3),
                    "handshake_ms": round(res["t_handshake_ms"], 3),
                    "authorize_ms": round(res["t_authorize_ms"], 3),
                    "token_ms": round(res["t_token_ms"], 3),
                    "verify_ms": round(res["t_jwt_verify_ms"], 3),
                    "resource_ms": round(res["t_userinfo_ms"], 3),
                    "pop_ms": round(res["t_pop_verify_ms"], 3),
                    "jwt_sign_ms": round(res["t_jwt_sign_ms"], 3),
                    "replay_blocked": res["replay_blocked"],
                    "iteration": i
                })

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "run_id", "protocol", "scenario", "auth_total_ms", "full_cycle_ms",
            "handshake_ms", "authorize_ms", "token_ms", "verify_ms", "resource_ms", "pop_ms",
            "jwt_sign_ms", "replay_blocked", "iteration"
        ])
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"[*] OIDC benchmarks saved to {csv_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--environment-profile", default=None)
    args = parser.parse_args()
    
    run_benchmark({
        "repeat": args.repeat,
        "warmup": args.warmup,
        "run_id": args.run_id,
        "results_dir": args.results_dir
    })
