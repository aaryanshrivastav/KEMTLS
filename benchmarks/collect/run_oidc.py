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

from crypto.ml_kem import MLKEM768
from kemtls.handshake import ClientHandshake, ServerHandshake
from kemtls.pdk import PDKTrustStore
from oidc.auth_endpoints import InMemoryClientRegistry
from servers.auth_server_app import create_auth_server_app
from servers.resource_server_app import create_resource_server_app
from telemetry.collector import KEMTLSHandshakeCollector, OIDCTokenCollector, OIDCUserinfoCollector, OIDCClientFlowCollector
from utils.encoding import base64url_decode, base64url_encode
from utils.helpers import generate_random_string
import hashlib


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
        "auth_pk": base64url_decode(as_config["longterm_pk"]),
        "auth_cert": as_config["certificate"],
        "auth_pdk_key_id": as_config.get("pdk_key_id", "as-key-1"),
        "resource_sk": base64url_decode(rs_config["longterm_sk"]),
        "resource_pk": base64url_decode(rs_config["longterm_pk"]),
        "resource_cert": rs_config["certificate"],
        "resource_pdk_key_id": rs_config.get("pdk_key_id", "rs-key-1"),
        "pdk_store": pdk_store,
        "pdk_manifest": pdk_manifest,
    }


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "avg": statistics.mean(values),
        "median": statistics.median(values),
        "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))],
    }


def _build_apps(mode: str, keys: Dict[str, Any]):
    issuer_url = "https://issuer.example"
    client_redirect_uri = "https://client.example/cb"
    client_config = {
        "client123": {"redirect_uris": [client_redirect_uri]},
    }

    auth_app = create_auth_server_app(
        {
            "issuer": issuer_url,
            "issuer_public_key": keys["auth_jwt_pk"],
            "issuer_secret_key": keys["auth_jwt_sk"],
            "clients": client_config,
            "demo_user": "alice",
            "introspection_endpoint": f"{issuer_url}/introspect",
            "kemtls_modes_supported": [mode, "auto"],
        },
        stores={"client_registry": InMemoryClientRegistry(client_config)},
    )
    resource_app = create_resource_server_app(
        {
            "issuer": issuer_url,
            "issuer_public_key": keys["auth_jwt_pk"],
            "resource_audience": "client123",
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
    return session, client_collector.get_metrics(), server_collector.get_metrics()


def _flow_bytes(payload: Dict[str, Any]) -> int:
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _run_flow(mode: str, config: Dict[str, Any], keys: Dict[str, Any]) -> Dict[str, Any]:
    auth_app, resource_app = _build_apps(mode, keys)
    auth_endpoint = auth_app.extensions["auth_endpoint"]
    token_endpoint = auth_app.extensions["token_endpoint"]
    discovery_endpoint = auth_app.extensions["discovery_endpoint"]
    userinfo_endpoint = resource_app.extensions["userinfo_endpoint"]

    session, handshake_client_metrics, handshake_server_metrics = _build_session(mode, keys)
    issuer_url = "https://issuer.example"
    client_id = "client123"
    redirect_uri = "https://client.example/cb"
    scope = "openid profile email"
    verifier = generate_random_string(64)
    challenge = base64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    flow_collector = OIDCClientFlowCollector()
    flow_collector.start_flow()

    # 1. Discovery
    t0 = time.perf_counter_ns()
    discovery = discovery_endpoint.get_configuration()
    flow_collector.t_discovery_ns = time.perf_counter_ns() - t0

    # 2. Authorization
    t0 = time.perf_counter_ns()
    authorize_result = auth_endpoint.handle_authorize_request(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=generate_random_string(16),
        nonce=generate_random_string(16),
        user_id="alice",
        response_type="code",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    flow_collector.t_authorize_ns = time.perf_counter_ns() - t0
    if "code" not in authorize_result:
        raise ValueError(f"Authorization failed: {authorize_result}")
    authorization_code = authorize_result["code"]

    # 3. Token exchange
    token_collector = OIDCTokenCollector()
    token_collector.grant_type = "authorization_code"
    t0 = time.perf_counter_ns()
    token_result = token_endpoint.handle_token_request(
        grant_type="authorization_code",
        client_id=client_id,
        redirect_uri=redirect_uri,
        code=authorization_code,
        code_verifier=verifier,
        session=session,
        collector=token_collector,
    )
    flow_collector.t_token_exchange_ns = time.perf_counter_ns() - t0
    if "access_token" not in token_result:
        raise ValueError(f"Token exchange failed: {token_result}")

    # 4. Userinfo
    userinfo_collector = OIDCUserinfoCollector()
    t0 = time.perf_counter_ns()
    userinfo_result, userinfo_status = userinfo_endpoint.handle_userinfo_request(
        token_result["access_token"],
        session=session,
        collector=userinfo_collector,
    )
    flow_collector.t_userinfo_ns = time.perf_counter_ns() - t0
    if userinfo_status != 200:
        raise ValueError(f"Userinfo failed: {userinfo_result}")

    # 5. Refresh
    refresh_collector = OIDCTokenCollector()
    refresh_collector.grant_type = "refresh_token"
    t0 = time.perf_counter_ns()
    refresh_result = token_endpoint.handle_token_request(
        grant_type="refresh_token",
        client_id=client_id,
        refresh_token=token_result["refresh_token"],
        session=session,
        collector=refresh_collector,
    )
    refresh_ns = time.perf_counter_ns() - t0
    if "access_token" not in refresh_result:
        raise ValueError(f"Refresh failed: {refresh_result}")

    flow_collector.t_tls_handshake_ns = handshake_client_metrics["hct_ms"] * 1_000_000
    flow_collector.id_token_size = len(token_result.get("id_token", ""))
    flow_collector.access_token_size = len(token_result.get("access_token", ""))
    flow_collector.refresh_token_size = len(token_result.get("refresh_token", ""))
    flow_collector.scopes = scope
    flow_collector.end_flow()

    token_sizes = token_collector.get_metrics()["token_sizes"]
    refresh_sizes = refresh_collector.get_metrics()["token_sizes"]
    token_sign_ns = token_collector.get_metrics()["t_jwt_sign_ns"]
    token_verify_ns = userinfo_collector.get_metrics()["t_verify_ns"]
    binding_verify_ns = userinfo_collector.get_metrics()["t_binding_verify_ns"]

    return {
        "mode": mode,
        "t_discovery_ms": flow_collector.get_metrics()["t_discovery_ms"],
        "t_authorize_ms": flow_collector.get_metrics()["t_authorize_ms"],
        "t_token_ms": flow_collector.get_metrics()["t_token_exchange_ms"],
        "t_userinfo_ms": flow_collector.get_metrics()["t_userinfo_ms"],
        "t_refresh_ms": refresh_ns / 1_000_000,
        "t_auth_total_ms": flow_collector.get_metrics()["t_total_flow_ms"],
        "t_login_to_resource_ms": flow_collector.get_metrics()["t_discovery_ms"]
        + flow_collector.get_metrics()["t_authorize_ms"]
        + flow_collector.get_metrics()["t_token_exchange_ms"]
        + flow_collector.get_metrics()["t_userinfo_ms"],
        "t_tls_hs_ms": flow_collector.get_metrics()["t_tls_handshake_ms"],
        "t_jwt_sign_ms": token_sign_ns / 1_000_000,
        "t_jwt_verify_ms": token_verify_ns / 1_000_000,
        "t_binding_verify_ms": binding_verify_ns / 1_000_000,
        "s_id_token_bytes": flow_collector.id_token_size,
        "s_id_token_header": token_sizes.get("header", 0),
        "s_id_token_payload": token_sizes.get("payload", 0),
        "s_id_token_sig": token_sizes.get("signature", 0),
        "s_access_token_bytes": flow_collector.access_token_size,
        "s_refresh_token_bytes": flow_collector.refresh_token_size,
        "s_total_request_bytes": _flow_bytes(
            {
                "authorize": authorize_result,
                "token_request": {
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "code": authorization_code,
                    "code_verifier": verifier,
                },
                "userinfo_request": {"Authorization": f"Bearer {token_result['access_token']}"},
                "refresh_request": {
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": token_result["refresh_token"],
                },
            }
        ),
        "s_total_response_bytes": _flow_bytes(
            {
                "discovery": discovery,
                "token": token_result,
                "userinfo": userinfo_result,
                "refresh": refresh_result,
            }
        ),
        "handshake_mode": handshake_client_metrics["mode"],
        "session_binding_id": session.session_binding_id,
        "refresh_binding_id": session.refresh_binding_id,
    }


def run_benchmark(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    warmup = int(config.get("warmup", 50))
    repeat = int(config.get("repeat", 1000))
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    csv_path = raw_dir / "oidc_results.csv"
    summary_path = raw_dir / "oidc_summary.json"
    keys = _load_keys()

    print("Running OIDC benchmark suite...")
    print(f"[*] run_id={run_id}")
    print(f"[*] environment_profile={environment_profile}")
    print(f"[*] warmup={warmup} repeat={repeat}")

    for _ in range(warmup):
        _run_flow("baseline", config, keys)
        _run_flow("pdk", config, keys)

    rows: List[Dict[str, Any]] = []
    summaries: Dict[str, Dict[str, float]] = {}

    for mode in ("baseline", "pdk"):
        mode_rows: List[Dict[str, Any]] = []
        t_auth_total_values: List[float] = []
        t_token_values: List[float] = []
        t_userinfo_values: List[float] = []

        for iteration in range(repeat):
            result = _run_flow(mode, config, keys)
            t_auth_total_values.append(float(result["t_auth_total_ms"]))
            t_token_values.append(float(result["t_token_ms"]))
            t_userinfo_values.append(float(result["t_userinfo_ms"]))

            row = {
                "run_id": run_id,
                "protocol": "OIDC",
                "scenario": mode,
                "t_discovery_ms": round(float(result["t_discovery_ms"]), 3),
                "t_authorize_ms": round(float(result["t_authorize_ms"]), 3),
                "t_token_ms": round(float(result["t_token_ms"]), 3),
                "t_userinfo_ms": round(float(result["t_userinfo_ms"]), 3),
                "t_refresh_ms": round(float(result["t_refresh_ms"]), 3),
                "t_auth_total_ms": round(float(result["t_auth_total_ms"]), 3),
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
                "handshake_mode": result["handshake_mode"],
                "iteration": iteration,
                "environment_profile": environment_profile,
            }
            rows.append(row)
            mode_rows.append(row)

        summaries[mode] = {
            "t_auth_total": _stats(t_auth_total_values),
            "t_token": _stats(t_token_values),
            "t_userinfo": _stats(t_userinfo_values),
        }

    with csv_path.open("w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=[
                "run_id",
                "protocol",
                "scenario",
                "t_discovery_ms",
                "t_authorize_ms",
                "t_token_ms",
                "t_userinfo_ms",
                "t_refresh_ms",
                "t_auth_total_ms",
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
                "handshake_mode",
                "iteration",
                "environment_profile",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    summary_path.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(f"[*] OIDC benchmarks saved to {csv_path}")
    print(f"[*] OIDC summary saved to {summary_path}")
    return csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real OIDC benchmarks")
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
