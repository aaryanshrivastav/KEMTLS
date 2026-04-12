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

# Ensure src is in path for all sub-imports
sys.path.insert(0, str(SRC_DIR))

from kemtls.client import KEMTLSClient
from telemetry.collector import KEMTLSHandshakeCollector
from runtime_support import BenchmarkStack, latest_metric

# Crypto classes for monkeypatching
from crypto.ml_kem import MLKEM768
from crypto.ml_dsa import MLDSA65
from crypto.aead import AEADCipher
from crypto.key_schedule import KeyDerivation

# Global tracking for crypto timings
CRYPTO_TIMES = {
    "kem_encap": 0.0,
    "kem_decap": 0.0,
    "dsa_sign": 0.0,
    "dsa_verify": 0.0,
    "hkdf": 0.0,
    "aead_setup": 0.0,
}

# Original unpatched methods
orig_encapsulate = MLKEM768.encapsulate
orig_decapsulate = MLKEM768.decapsulate
orig_sign = MLDSA65.sign
orig_verify = MLDSA65.verify
orig_derive = KeyDerivation.derive_session_keys
orig_aead_init = AEADCipher.__init__

def patch_crypto():
    def wrapped_encap(*args, **kwargs):
        t0 = time.perf_counter_ns()
        res = orig_encapsulate(*args, **kwargs)
        CRYPTO_TIMES["kem_encap"] += (time.perf_counter_ns() - t0) / 1000000.0
        return res
        
    def wrapped_decap(*args, **kwargs):
        t0 = time.perf_counter_ns()
        res = orig_decapsulate(*args, **kwargs)
        CRYPTO_TIMES["kem_decap"] += (time.perf_counter_ns() - t0) / 1000000.0
        return res
        
    def wrapped_sign(*args, **kwargs):
        t0 = time.perf_counter_ns()
        res = orig_sign(*args, **kwargs)
        CRYPTO_TIMES["dsa_sign"] += (time.perf_counter_ns() - t0) / 1000000.0
        return res
        
    def wrapped_verify(*args, **kwargs):
        t0 = time.perf_counter_ns()
        res = orig_verify(*args, **kwargs)
        CRYPTO_TIMES["dsa_verify"] += (time.perf_counter_ns() - t0) / 1000000.0
        return res
        
    def wrapped_derive(*args, **kwargs):
        t0 = time.perf_counter_ns()
        res = orig_derive(*args, **kwargs)
        CRYPTO_TIMES["hkdf"] += (time.perf_counter_ns() - t0) / 1000000.0
        return res
        
    def wrapped_aead_init(self, *args, **kwargs):
        t0 = time.perf_counter_ns()
        orig_aead_init(self, *args, **kwargs)
        CRYPTO_TIMES["aead_setup"] += (time.perf_counter_ns() - t0) / 1000000.0

    MLKEM768.encapsulate = wrapped_encap
    MLKEM768.decapsulate = wrapped_decap
    MLDSA65.sign = wrapped_sign
    MLDSA65.verify = wrapped_verify
    KeyDerivation.derive_session_keys = wrapped_derive
    AEADCipher.__init__ = wrapped_aead_init

def unpatch_crypto():
    MLKEM768.encapsulate = orig_encapsulate
    MLKEM768.decapsulate = orig_decapsulate
    MLDSA65.sign = orig_sign
    MLDSA65.verify = orig_verify
    KeyDerivation.derive_session_keys = orig_derive
    AEADCipher.__init__ = orig_aead_init


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "avg": statistics.mean(values),
        "median": statistics.median(values),
        "p50": statistics.median(values),
        "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
        "p99": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.99))],
    }


def _protocol_modes(protocols: Iterable[str]) -> List[str]:
    normalized = {str(item).lower() for item in protocols}
    modes: List[str] = []
    if "kemtls" in normalized or "baseline" in normalized:
        modes.append("baseline")
    if "kemtls_pdk" in normalized or "pdk" in normalized:
        modes.append("pdk")
    return modes or ["baseline", "pdk"]


def _run_handshake(
    *,
    mode: str,
    stack: BenchmarkStack,
    port: int,
    server_metrics_queue,
    rtt_ms: int,
) -> Dict[str, Any]:
    # Reset crypto timers inside run
    for k in CRYPTO_TIMES:
        CRYPTO_TIMES[k] = 0.0
        
    collector = KEMTLSHandshakeCollector()
    client = KEMTLSClient(
        expected_identity="auth-server",
        ca_pk=stack.keys["ca_pk"],
        pdk_store=stack.keys["pdk_store"],
        mode=mode,
        collector=collector,
        transport="tcp",
    )
    
    # RTT Simulation using patched send/recv
    import kemtls.tcp_transport
    if rtt_ms > 0:
        orig_send = kemtls.tcp_transport.KEMTLSTCPClientTransport.send_handshake
        orig_recv = kemtls.tcp_transport.KEMTLSTCPClientTransport.recv_handshake
        
        def mock_send(self, payload: bytes, *, sock=None):
            time.sleep((rtt_ms / 2) / 1000.0)
            orig_send(self, payload, sock=sock)
            
        def mock_recv(self, *, sock=None):
            time.sleep((rtt_ms / 2) / 1000.0)
            return orig_recv(self, sock=sock)

        kemtls.tcp_transport.KEMTLSTCPClientTransport.send_handshake = mock_send
        kemtls.tcp_transport.KEMTLSTCPClientTransport.recv_handshake = mock_recv

    start_ns = time.perf_counter_ns()
    
    try:
        response, session = client.request(
            host=stack.host,
            port=port,
            method="GET",
            path="/health",
            headers={"Accept": "application/json"},
        )
    finally:
        if rtt_ms > 0:
            kemtls.tcp_transport.KEMTLSTCPClientTransport.send_handshake = orig_send
            kemtls.tcp_transport.KEMTLSTCPClientTransport.recv_handshake = orig_recv

    total_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    client.close()

    server_metrics = None
    deadline = time.time() + 1.0
    while server_metrics is None and time.time() < deadline:
        server_metrics = latest_metric(server_metrics_queue)
        if server_metrics is None:
            time.sleep(0.01)

    client_metrics = collector.get_metrics()
    
    return {
        "mode": mode,
        "latency_ms": total_ms,
        "hct_client_ms": float(client_metrics["hct_ms"]),
        "hct_server_ms": float((server_metrics or {}).get("hct_ms", 0.0)),
        "bytes_client_to_server": int(client_metrics["client_hello_size"]) + int(client_metrics["client_key_exchange_size"]) + int(client_metrics["client_finished_size"]),
        "bytes_server_to_client": int(client_metrics["server_hello_size"]) + int(client_metrics["server_finished_size"]),
        "bytes_total": int(client_metrics["total_handshake_bytes"]),
        "tcp_segments": max(1, (int(client_metrics["total_handshake_bytes"]) + 1439) // 1440),
        "t_kem_encap_ms": CRYPTO_TIMES["kem_encap"],
        "t_kem_decap_ms": CRYPTO_TIMES["kem_decap"],
        "t_hkdf_ms": CRYPTO_TIMES["hkdf"],
        "t_aead_setup_ms": CRYPTO_TIMES["aead_setup"],
        "t_dsa_sign_ms": CRYPTO_TIMES["dsa_sign"],
        "t_dsa_verify_ms": CRYPTO_TIMES["dsa_verify"],
        "rtt_ms": rtt_ms,
    }


def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    scenario = str((config.get("scenarios") or ["loopback"])[0])
    warmup = int(config.get("warmup", 50))
    repeat = int(config.get("repeat", 1000))
    protocols = list(config.get("protocols", ["kemtls", "kemtls_pdk"]))
    # Supported RTTs: 0, 10, 50, 100
    rtts = [0, 10, 50, 100]
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw_dir / "handshake.csv"
    summary_path = raw_dir / "handshake_summary.json"

    print("Running layer A handshake benchmarks...")
    
    rows: List[Dict[str, Any]] = []
    summaries: Dict[str, Dict[str, Any]] = {}

    patch_crypto()

    with BenchmarkStack(transport="tcp") as stack:
        probe_handle = stack.start_probe_server()
        modes = _protocol_modes(protocols)

        for mode in modes:
            for rtt_ms in rtts:
                print(f"[*] Handshake -> Mode: {mode}, RTT: {rtt_ms}ms")
                for _ in range(warmup):
                    _run_handshake(
                        mode=mode,
                        stack=stack,
                        port=probe_handle.port,
                        server_metrics_queue=probe_handle.handshake_metrics,
                        rtt_ms=rtt_ms,
                    )

                latency_values: List[float] = []
                bytes_values: List[float] = []

                for iteration in range(repeat):
                    result = _run_handshake(
                        mode=mode,
                        stack=stack,
                        port=probe_handle.port,
                        server_metrics_queue=probe_handle.handshake_metrics,
                        rtt_ms=rtt_ms,
                    )
                    latency_values.append(float(result["latency_ms"]))
                    bytes_values.append(float(result["bytes_total"]))
                    rows.append(
                        {
                            "run_id": run_id,
                            "protocol": "KEMTLS",
                            "scenario": scenario,
                            "handshake_mode": mode,
                            "rtt_ms": rtt_ms,
                            "latency_ms": round(float(result["latency_ms"]), 3),
                            "bytes_client_to_server": int(result["bytes_client_to_server"]),
                            "bytes_server_to_client": int(result["bytes_server_to_client"]),
                            "bytes_total": int(result["bytes_total"]),
                            "segments": int(result["tcp_segments"]),
                            "t_kem_encap_ms": round(float(result["t_kem_encap_ms"]), 3),
                            "t_kem_decap_ms": round(float(result["t_kem_decap_ms"]), 3),
                            "t_hkdf_ms": round(float(result["t_hkdf_ms"]), 3),
                            "t_aead_setup_ms": round(float(result["t_aead_setup_ms"]), 3),
                            "t_dsa_sign_ms": round(float(result["t_dsa_sign_ms"]), 3),
                            "t_dsa_verify_ms": round(float(result["t_dsa_verify_ms"]), 3),
                            "iteration": iteration,
                        }
                    )

                key = f"{mode}_rtt{rtt_ms}"
                summaries[key] = {
                    "latency": _stats(latency_values),
                    "bytes": _stats(bytes_values),
                }

    unpatch_crypto()

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "run_id", "protocol", "scenario", "handshake_mode", "rtt_ms",
                "latency_ms", "bytes_client_to_server", "bytes_server_to_client", "bytes_total", "segments",
                "t_kem_encap_ms", "t_kem_decap_ms", "t_hkdf_ms", "t_aead_setup_ms",
                "t_dsa_sign_ms", "t_dsa_verify_ms", "iteration"
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(f"[*] Handshake benchmarks saved to {csv_path}")
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repeat", type=int, default=10) # Default to 10 for quick testing
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--environment-profile", default=None)
    args = parser.parse_args()

    config_path = (SCRIPT_DIR / args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    if args.results_dir: config["results_dir"] = args.results_dir
    if args.run_id: config["run_id"] = args.run_id
    if args.repeat is not None: config["repeat"] = args.repeat
    if args.warmup is not None: config["warmup"] = args.warmup

    run_benchmark(config)


if __name__ == "__main__":
    main()
