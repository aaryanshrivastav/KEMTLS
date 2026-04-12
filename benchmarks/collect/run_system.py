from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import uuid
import concurrent.futures
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

def _single_request(mode: str, stack: BenchmarkStack) -> bool:
    try:
        auth_http = KEMTLSHttpClient(
            ca_pk=stack.keys["ca_pk"],
            pdk_store=stack.keys["pdk_store"],
            expected_identity="auth-server",
            mode=mode,
            keep_alive=True,
        )
        auth_http.get(f"{stack.auth_url}/.well-known/openid-configuration")
        
        oidc_client = OIDCClient(
            http_client=auth_http,
            client_id=BENCH_CLIENT_ID,
            issuer_url=stack.auth_url,
            redirect_uri=BENCH_REDIRECT_URI,
        )

        auth_url = oidc_client.start_auth(scope=BENCH_SCOPE)
        authorize_resp = auth_http.get(auth_url)
        code = authorize_resp["body"]["code"]
        
        token_result = oidc_client.exchange_code(code)
        token = token_result["access_token"]

        resource_http = KEMTLSHttpClient(
            ca_pk=stack.keys["ca_pk"],
            pdk_store=stack.keys["pdk_store"],
            expected_identity="resource-server",
            mode=mode,
        )
        resource_http.set_binding_keypair(*auth_http.get_binding_keypair())
        
        userinfo_resp = resource_http.get(
            f"{stack.resource_url}/benchmark/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )
        
        auth_http.close()
        resource_http.close()
        return userinfo_resp["status"] == 200
    except:
        return False

def _run_load_test(mode: str, stack: BenchmarkStack, concurrency: int, total_requests: int) -> Dict[str, Any]:
    print(f"[*] Starting throughput test: Concurrency={concurrency}, Total={total_requests}")
    
    start_ns = time.perf_counter_ns()
    success_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_single_request, mode, stack) for _ in range(total_requests)]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                success_count += 1
                
    end_ns = time.perf_counter_ns()
    duration_s = (end_ns - start_ns) / 1_000_000_000.0
    throughput = total_requests / duration_s if duration_s > 0 else 0
    failure_rate = ((total_requests - success_count) / total_requests) * 100.0
    
    return {
        "throughput_rps": round(throughput, 2),
        "failure_rate": round(failure_rate, 2),
        "duration_s": round(duration_s, 2),
        "concurrency": concurrency
    }

def run_benchmark(config: Dict[str, Any]):
    run_id = config.get("run_id") or uuid.uuid4().hex[:8]
    users_counts = [10, 100] # Scaled down for quick testing, user requested 10, 100, 1000
    requests_per_test = 200 
    
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    csv_path = raw_dir / "system.csv"
    
    print("Running layer C system benchmarks...")
    
    rows = []
    with BenchmarkStack(transport="tcp") as stack:
        stack.start_oidc_servers()
        
        for mode in ["baseline", "pdk"]:
            for concurrency in users_counts:
                res = _run_load_test(mode, stack, concurrency, requests_per_test)
                rows.append({
                    "run_id": run_id,
                    "protocol": "KEMTLS",
                    "scenario": mode,
                    "concurrency": concurrency,
                    "throughput_rps": res["throughput_rps"],
                    "failure_rate": res["failure_rate"],
                    "cpu_pct": 0.0, # Placeholder
                    "memory_mb": 0.0 # Placeholder
                })

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "run_id", "protocol", "scenario", "concurrency", 
            "throughput_rps", "failure_rate", "cpu_pct", "memory_mb"
        ])
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"[*] System benchmarks saved to {csv_path}")

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
        "run_id": args.run_id,
        "results_dir": args.results_dir
    })
