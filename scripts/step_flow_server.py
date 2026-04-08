"""
Socket.IO orchestrator for the step-by-step KEMTLS + OIDC demo.

This service executes handshake + OIDC contract exchange steps against real
protocol code and streams step/log events to the frontend.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
import hashlib
from urllib.parse import parse_qs, urlparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, request
from flask_socketio import SocketIO, emit

# Ensure src in path
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from kemtls.handshake import ClientHandshake, ServerHandshake
from client.kemtls_http_client import KEMTLSHttpClient
from client.oidc_client import OIDCClient
from utils.encoding import base64url_decode, base64url_encode
from utils.serialization import deserialize_message


STEP_ORDER = ["hello", "server", "derive", "finished", "authorize", "account_auth", "consent", "token_exchange", "session_bind", "resource_access"]
SIMULATION_MODE = os.environ.get("SIMULATION_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}


class ResourceServerUnavailableError(RuntimeError):
    """Raised when the resource server is unreachable and simulation is disabled."""

    def __init__(self):
        super().__init__("Resource server unavailable")
        self.payload = {"status": "error", "message": "Resource server unavailable"}


@dataclass
class HandshakeSessionState:
    run_id: str = ""
    client_sid: str = ""
    mode: str = "auto"
    step_index: int = 0
    auto_advance: bool = False
    status: str = "idle"
    client: Optional[ClientHandshake] = None
    server: Optional[ServerHandshake] = None
    ch_bytes: Optional[bytes] = None
    sh_bytes: Optional[bytes] = None
    cke_bytes: Optional[bytes] = None
    sf_bytes: Optional[bytes] = None
    client_session: Any = None
    server_session: Any = None
    http_client: Optional[KEMTLSHttpClient] = None
    oidc_client: Optional[OIDCClient] = None
    auth_code: Optional[str] = None
    token_response: Optional[Dict[str, Any]] = None
    token_claims: Optional[Dict[str, Any]] = None
    token_transport_binding_id: Any = None
    oidc_issuer_url: str = ""
    oidc_redirect_uri: str = ""
    oidc_client_id: str = ""
    oidc_scope: str = "openid profile email"
    resource_http_client: Optional[KEMTLSHttpClient] = None
    resource_url: str = ""
    started_at: float = field(default_factory=time.perf_counter)


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

_active_session: Optional[HandshakeSessionState] = None
_active_run_id: Optional[str] = None


def _now_ms() -> int:
    return int(time.time() * 1000)


def _load_auth_material() -> Dict[str, Any]:
    keys_dir = ROOT_DIR / "keys"
    ca_keys_path = keys_dir / "ca" / "ca_keys.json"
    as_config_path = keys_dir / "auth_server" / "as_config.json"

    if not ca_keys_path.exists() or not as_config_path.exists():
        raise RuntimeError("Key artifacts not found. Run scripts/bootstrap_ca.py first.")

    with open(ca_keys_path, "r", encoding="utf-8") as f:
        ca_keys = json.load(f)
    with open(as_config_path, "r", encoding="utf-8") as f:
        as_config = json.load(f)

    return {
        "ca_pk": base64url_decode(ca_keys["public_key"]),
        "server_lt_sk": base64url_decode(as_config["longterm_sk"]),
        "server_cert": as_config["certificate"],
        "server_identity": as_config.get("identity", "auth-server"),
    }


def _load_oidc_runtime_config() -> Dict[str, str]:
    config_path = ROOT_DIR / "config" / "client_config.json"
    defaults = {
        "client_id": "demo-client",
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email",
    }

    if not config_path.exists():
        return defaults

    with open(config_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)

    defaults["client_id"] = loaded.get("client_id", defaults["client_id"])
    defaults["redirect_uri"] = loaded.get("redirect_uri", defaults["redirect_uri"])
    defaults["scope"] = loaded.get("scope", defaults["scope"])
    return defaults


def _emit_event(event: str, payload: Dict[str, Any], sid_override: Optional[str] = None) -> None:
    sid = sid_override
    if not sid and _active_session and _active_session.client_sid:
        sid = _active_session.client_sid
    if sid:
        socketio.emit(event, payload, to=sid)
    else:
        socketio.emit(event, payload)


def _emit_log(message: str, level: str = "info") -> None:
    _emit_event(
        "log",
        {
            "message": message,
            "level": level,
            "timestamp": _now_ms(),
            "runId": _active_run_id,
        },
    )


def _close_active_session() -> None:
    global _active_session, _active_run_id
    if _active_session and _active_session.http_client:
        _active_session.http_client.close()
    if _active_session and _active_session.resource_http_client:
        _active_session.resource_http_client.close()
    _active_session = None
    _active_run_id = None


def _reset_active_run(message: Optional[str] = None) -> None:
    _close_active_session()
    if message:
        _emit_event("step_flow_reset", {"timestamp": _now_ms(), "message": message})
    else:
        _emit_event("step_flow_reset", {"timestamp": _now_ms()})


def _initialize_state(mode: str, run_id: str, auto_advance: bool = False, client_sid: str = "") -> HandshakeSessionState:
    material = _load_auth_material()
    oidc_runtime = _load_oidc_runtime_config()
    http_client = KEMTLSHttpClient(
        ca_pk=material["ca_pk"],
        pdk_store=None,
        expected_identity=material["server_identity"],
        mode=mode,
        keep_alive=True,
    )
    oidc_issuer_url = "kemtls://127.0.0.1:4433"
    oidc_client = OIDCClient(
        http_client=http_client,
        client_id=oidc_runtime["client_id"],
        issuer_url=oidc_issuer_url,
        redirect_uri=oidc_runtime["redirect_uri"],
    )
    resource_http_client = KEMTLSHttpClient(
        ca_pk=material["ca_pk"],
        pdk_store=None,
        expected_identity="resource-server",
        mode=mode,
        keep_alive=True,
    )
    binding_public_key, binding_secret_key = http_client.get_binding_keypair()
    resource_http_client.set_binding_keypair(binding_public_key, binding_secret_key)
    resource_url = "kemtls://127.0.0.1:4434/userinfo"

    client = ClientHandshake(
        expected_identity=material["server_identity"],
        ca_pk=material["ca_pk"],
        pdk_store=None,
        mode=mode,
    )
    server = ServerHandshake(
        server_identity=material["server_identity"],
        server_lt_sk=material["server_lt_sk"],
        cert=material["server_cert"],
        pdk_key_id=None,
    )
    return HandshakeSessionState(
        run_id=run_id,
        client_sid=client_sid,
        mode=mode,
        auto_advance=auto_advance,
        status="running",
        client=client,
        server=server,
        http_client=http_client,
        oidc_client=oidc_client,
        oidc_issuer_url=oidc_issuer_url,
        oidc_client_id=oidc_runtime["client_id"],
        oidc_redirect_uri=oidc_runtime["redirect_uri"],
        oidc_scope=oidc_runtime["scope"],
        resource_http_client=resource_http_client,
        resource_url=resource_url,
    )


def _step_id_for_index(index: int) -> Optional[str]:
    if index < 0 or index >= len(STEP_ORDER):
        return None
    return STEP_ORDER[index]


def _emit_state_snapshot(sid_override: Optional[str] = None) -> None:
    if not _active_session:
        _emit_event(
            "step_flow_state",
            {
                "hasActiveRun": False,
                "timestamp": _now_ms(),
            },
            sid_override=sid_override,
        )
        return

    state = _active_session
    current_step_id = None
    next_step_id = None

    if state.status == "running":
        current_step_id = _step_id_for_index(state.step_index)
    elif state.status == "paused":
        current_step_id = _step_id_for_index(state.step_index - 1)
        next_step_id = _step_id_for_index(state.step_index)
    elif state.status == "done":
        current_step_id = _step_id_for_index(len(STEP_ORDER) - 1)

    _emit_event(
        "step_flow_state",
        {
            "hasActiveRun": True,
            "runId": state.run_id,
            "mode": state.mode,
            "status": state.status,
            "stepIndex": state.step_index,
            "currentStepId": current_step_id,
            "nextStepId": next_step_id,
            "timestamp": _now_ms(),
        },
        sid_override=sid_override,
    )


def _run_current_step(state: HandshakeSessionState) -> Dict[str, Any]:
    step_id = STEP_ORDER[state.step_index]
    started = time.perf_counter()

    if step_id == "hello":
        state.ch_bytes = state.client.client_hello()  # type: ignore[union-attr]
        payload = deserialize_message(state.ch_bytes)
        data = {
            "message_size": f"{len(state.ch_bytes)} bytes",
            "version": str(payload.get("version", "KEMTLS/1.0")),
            "modes": ",".join(payload.get("modes", [])) or state.mode,
        }

    elif step_id == "server":
        state.sh_bytes = state.server.process_client_hello(state.ch_bytes)  # type: ignore[union-attr]
        state.cke_bytes, state.client_session = state.client.process_server_hello(state.sh_bytes)  # type: ignore[union-attr]
        sh = deserialize_message(state.sh_bytes)
        cke = deserialize_message(state.cke_bytes)
        ct_eph = str(cke.get("ct_ephemeral", ""))
        data = {
            "server_hello_size": f"{len(state.sh_bytes)} bytes",
            "negotiated_mode": str(sh.get("mode", "baseline")),
            "ct_eph_size": f"{len(base64url_decode(ct_eph))} bytes" if ct_eph else "unknown",
        }

    elif step_id == "derive":
        state.sf_bytes = state.server.process_client_key_exchange(state.cke_bytes)  # type: ignore[union-attr]
        client_fin_key = getattr(state.client, "client_fin_key", b"") or b""
        server_fin_key = getattr(state.client, "server_fin_key", b"") or b""
        hs_secret = getattr(state.client, "handshake_secret", b"") or b""
        data = {
            "handshake_secret": f"{len(hs_secret)} bytes",
            "client_finished_key": f"{len(client_fin_key)} bytes",
            "server_finished_key": f"{len(server_fin_key)} bytes",
        }

    elif step_id == "finished":
        state.client.process_server_finished(state.sf_bytes, state.client_session)  # type: ignore[union-attr]
        cf_bytes = state.client.client_finished()  # type: ignore[union-attr]
        state.server_session = state.server.verify_client_finished(cf_bytes)  # type: ignore[union-attr]
        binding_id = getattr(state.server_session, "session_binding_id", "") or ""
        data = {
            "handshake_mac": "verified",
            "session_id": str(getattr(state.server_session, "session_id", "unknown")),
            "session_binding": _render_binding(binding_id) if binding_id else "n/a",
        }

    elif step_id == "authorize":
        if not state.oidc_client:
            raise RuntimeError("OIDC client is not initialized")

        auth_url = state.oidc_client.start_auth(scope=state.oidc_scope)
        response = state.oidc_client.http_client.get(auth_url)
        if response.get("status") != 200:
            raise RuntimeError(f"Authorize failed with status {response.get('status')}: {response.get('body')}")

        body = response.get("body", {})
        if not isinstance(body, dict):
            raise RuntimeError("Authorize response was not JSON")

        code = body.get("code")
        if not code:
            raise RuntimeError("Authorize response did not include an authorization code")

        state.auth_code = str(code)
        query = parse_qs(urlparse(auth_url).query)
        data = {
            "endpoint": "/authorize",
            "redirect": "accounts.google.com",
            "response_type": str(query.get("response_type", [""])[0] or "code"),
            "scope": str(query.get("scope", [state.oidc_scope])[0]),
            "code_challenge_method": str(query.get("code_challenge_method", ["S256"])[0]),
        }

    elif step_id == "account_auth":
        # Synthetic UI step — the user selects their account at the IdP.
        # No backend crypto work; the auth_code was already obtained in the
        # authorize step.  We just report metadata for the frontend.
        data = {
            "provider": "Google",
            "method": "session + MFA",
            "status": "authenticated",
        }

    elif step_id == "consent":
        # Synthetic UI step — user grants consent and the auth code is
        # confirmed.  The actual code was already captured during `authorize`.
        data = {
            "permissions": "name, email, profile picture",
            "auth_code": f"{(state.auth_code or '????')[:10]}...",
            "state_verified": "true",
        }

    elif step_id == "token_exchange":
        if not state.oidc_client:
            raise RuntimeError("OIDC client is not initialized")
        if not state.auth_code:
            raise RuntimeError("Authorization code missing. Run /authorize step first")

        state.token_response = state.oidc_client.exchange_code(state.auth_code)
        if not state.oidc_client.access_token:
            raise RuntimeError("Token endpoint response did not include an access token")

        state.token_claims = _decode_demo_access_token(state.oidc_client.access_token)
        token_telemetry = state.oidc_client.get_telemetry().get("tokens", [])
        if token_telemetry:
            state.token_transport_binding_id = token_telemetry[-1].get("binding_claim")
        if state.token_transport_binding_id is None and state.oidc_client.http_client:
            active_session = getattr(state.oidc_client.http_client.client, "session", None)
            if active_session is not None:
                state.token_transport_binding_id = getattr(active_session, "session_binding_id", None)

        signature_bytes = _extract_signature_bytes(state.oidc_client.access_token)
        data = {
            "endpoint": "/token",
            "grant_type": "authorization_code",
            "token_type": str((state.token_response or {}).get("token_type", "Bearer")),
            "access_token_sig": f"{len(signature_bytes)} bytes",
            "refresh_token": "issued" if (state.token_response or {}).get("refresh_token") else "missing",
        }

    elif step_id == "session_bind":
        if not state.oidc_client or not state.oidc_client.access_token:
            raise RuntimeError("Access token missing. Run token exchange first")
        if state.token_claims is None:
            raise RuntimeError("Token claims unavailable for binding verification")

        cnf = state.token_claims.get("cnf")
        cnf_kbh = cnf.get("kbh") if isinstance(cnf, dict) else None
        cnf_jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        token_claim_binding = state.token_claims.get("session_binding_id")
        transport_binding = state.token_transport_binding_id
        display_token_binding = token_claim_binding
        display_transport_binding = transport_binding

        matched = False
        match_mode = "session_binding_id"
        if isinstance(cnf_kbh, str) and transport_binding is not None:
            transport_bytes = transport_binding if isinstance(transport_binding, bytes) else str(transport_binding).encode("utf-8")
            expected_kbh = _base64url_nopad(hashlib.sha256(transport_bytes).digest())
            matched = cnf_kbh == expected_kbh
            match_mode = "cnf.kbh"
            display_token_binding = cnf_kbh
            display_transport_binding = expected_kbh
        elif isinstance(cnf_jwk, dict):
            current_public_key = None
            if state.oidc_client and state.oidc_client.http_client:
                current_public_key = state.oidc_client.http_client.binding_public_key
            claimed_public_key = cnf_jwk.get("x")
            if current_public_key is not None and isinstance(claimed_public_key, str):
                matched = base64url_encode(current_public_key) == claimed_public_key
                match_mode = "cnf.jwk"
                display_token_binding = claimed_public_key
                display_transport_binding = base64url_encode(current_public_key)
        else:
            matched = (
                token_claim_binding is not None
                and transport_binding is not None
                and token_claim_binding == transport_binding
            )

        if not matched:
            raise RuntimeError("Token contract binding mismatch: token claim does not match KEMTLS session binding")

        data = {
            "binding_contract": "verified",
            "match_mode": match_mode,
            "token_claim_binding": _render_binding(display_token_binding),
            "transport_binding": _render_binding(display_transport_binding),
            "verdict": "session-bound token accepted",
        }

    elif step_id == "resource_access":
        if not state.oidc_client or not state.oidc_client.access_token:
            raise RuntimeError("Access token missing. Run token exchange first")

        # Attempt real resource server call, fall back to simulation if unavailable.
        rs_available = False
        if state.resource_http_client:
            try:
                response = state.resource_http_client.get(
                    state.resource_url,
                    headers={
                        "Authorization": f"Bearer {state.oidc_client.access_token}",
                    },
                )
                status = int(response.get("status", 0) or 0)
                body = response.get("body")
                body_map = body if isinstance(body, dict) else {}
                outcome = "granted" if status == 200 else "denied"
                data = {
                    "endpoint": "/userinfo",
                    "status": str(status),
                    "outcome": outcome,
                    "server_message": str(body_map.get("sub") or body_map.get("message") or body_map.get("error") or "n/a"),
                    "binding_check": "passed" if status == 200 else "failed",
                }
                if status == 200:
                    data["expected_demo_result"] = "session binding matched"
                rs_available = True
            except Exception as e:
                _emit_log(f"  Resource server call failed: {str(e)}", "error")
                print(f"[ERROR] Resource server access failed: {e}")
                pass

        if not rs_available:
            if not SIMULATION_MODE:
                raise ResourceServerUnavailableError()

            _emit_log("  Resource server unreachable — simulation mode enabled", "warning")
            binding_id = getattr(state.server_session, "session_binding_id", "") or "demo-binding"
            data = {
                "endpoint": "/userinfo",
                "status": "error",
                "message": "Resource server unavailable",
                "simulated": True,
                "rs_binding": _render_binding(binding_id),
            }

    else:
        raise ValueError(f"Unknown step id: {step_id}")

    duration_ms = int((time.perf_counter() - started) * 1000)
    return {
        "stepId": step_id,
        "durationMs": max(duration_ms, 1),
        "data": data,
    }


def _decode_demo_access_token(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) == 2:
        payload_part = parts[0]
    elif len(parts) == 3:
        payload_part = parts[1]
    else:
        raise ValueError("Unexpected access token format")

    payload_bytes = base64url_decode(payload_part)
    payload = json.loads(payload_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Token payload is not an object")
    return payload


def _extract_signature_bytes(token: str) -> bytes:
    parts = token.split(".")
    if len(parts) == 2:
        return base64url_decode(parts[1])
    if len(parts) == 3:
        return base64url_decode(parts[2])
    raise ValueError("Unexpected access token format")


def _base64url_nopad(raw: bytes) -> str:
    return base64url_encode(raw)


def _render_binding(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()[:24] + "..."
    rendered = str(value)
    return rendered[:24] + "..." if len(rendered) > 24 else rendered


# Steps where the backend should only emit "start" and pause,
# waiting for the user to interact before completing.
INTERACTIVE_STEPS = {"account_auth", "consent"}


def _run_next_step_for_client() -> None:
    state = _active_session
    if not state:
        _emit_event("step_flow_error", {"message": "No active step-flow session."})
        return

    if state.step_index >= len(STEP_ORDER):
        state.status = "done"
        _emit_event(
            "step_flow_complete",
            {
                "success": True,
                "totalMs": int((time.perf_counter() - state.started_at) * 1000),
                "timestamp": _now_ms(),
                "runId": state.run_id,
            },
        )
        _emit_state_snapshot()
        return

    state.status = "running"
    step_id = STEP_ORDER[state.step_index]
    _emit_event("handshake_step_start", {"stepId": step_id, "timestamp": _now_ms(), "runId": state.run_id})

    # Interactive steps: emit start, then pause immediately.
    # The step logic runs only when the user continues (via _complete_interactive_step).
    if step_id in INTERACTIVE_STEPS and not state.auto_advance:
        _emit_log(f"[{step_id.upper()}] awaiting user interaction", "info")
        state.status = "paused"
        _emit_event("step_flow_paused", {"nextStepId": step_id, "timestamp": _now_ms(), "runId": state.run_id})
        _emit_state_snapshot()
        return

    _execute_and_advance(state, step_id)


def _complete_interactive_step() -> None:
    """Called when the user has interacted with an interactive step (account_auth/consent).
    Runs the step logic, emits complete, and advances."""
    state = _active_session
    if not state:
        _emit_event("step_flow_error", {"message": "No active step-flow session."})
        return

    step_id = STEP_ORDER[state.step_index]
    _execute_and_advance(state, step_id)


def _execute_and_advance(state: HandshakeSessionState, step_id: str) -> None:
    """Run the current step's logic, emit complete, and advance to the next step."""
    try:
        _emit_log(f"[{step_id.upper()}] starting", "info")
        result = _run_current_step(state)
        _emit_event(
            "handshake_step_complete",
            {
                "stepId": result["stepId"],
                "durationMs": result["durationMs"],
                "data": result["data"],
                "isFinal": state.step_index == (len(STEP_ORDER) - 1),
                "timestamp": _now_ms(),
                "runId": state.run_id,
            },
        )
        _emit_log(f"[{step_id.upper()}] complete ({result['durationMs']}ms)", "success")
        for key, value in result["data"].items():
            _emit_log(f"    {key}: {value}", "info")

        state.step_index += 1
        if state.step_index < len(STEP_ORDER):
            next_step = STEP_ORDER[state.step_index]
            if state.auto_advance:
                # Continue in background so full-flow mode runs end-to-end automatically.
                socketio.start_background_task(_run_next_step_for_client)
            elif next_step in INTERACTIVE_STEPS:
                # Auto-advance to interactive steps so they start and pause themselves.
                # This ensures the step shows as "running" on the login panel immediately.
                socketio.start_background_task(_run_next_step_for_client)
            else:
                state.status = "paused"
                _emit_event("step_flow_paused", {"nextStepId": next_step, "timestamp": _now_ms(), "runId": state.run_id})
                _emit_state_snapshot()
        else:
            state.status = "done"
            if state.http_client:
                state.http_client.close()
            if state.resource_http_client:
                state.resource_http_client.close()
            _emit_event(
                "step_flow_complete",
                {
                    "success": True,
                    "totalMs": int((time.perf_counter() - state.started_at) * 1000),
                    "timestamp": _now_ms(),
                    "runId": state.run_id,
                },
            )
            _emit_state_snapshot()
    except Exception as exc:
        state.status = "error"
        error_payload = str(exc)
        if isinstance(exc, ResourceServerUnavailableError):
            error_payload = exc.payload
        _emit_event(
            "step_flow_error",
            {
                "message": f"Step '{step_id}' failed",
                "error": error_payload,
                "timestamp": _now_ms(),
                "runId": state.run_id,
            },
        )
        _reset_active_run("stale session state cleared after step failure")
        _emit_state_snapshot()


@socketio.on("connect")
def on_connect() -> None:
    emit("connected", {"status": "ready", "timestamp": _now_ms()})
    if _active_session:
        _active_session.client_sid = request.sid
    _emit_state_snapshot(sid_override=request.sid)


@socketio.on("disconnect")
def on_disconnect() -> None:
    # Fail closed on disconnect: do not keep an in-memory run alive across
    # client reconnects, which can otherwise surface stale green-step state.
    _reset_active_run("client disconnected; cleared active run state")


@socketio.on("start_step_flow")
def on_start_step_flow(payload: Optional[Dict[str, Any]] = None) -> None:
    global _active_session, _active_run_id
    mode = str((payload or {}).get("mode", "auto"))
    auto_advance = bool((payload or {}).get("autoAdvance", False))
    _active_run_id = uuid.uuid4().hex
    _active_session = _initialize_state(mode, _active_run_id, auto_advance=auto_advance, client_sid=request.sid)

    emit(
        "step_flow_started",
        {
            "mode": mode,
            "autoAdvance": auto_advance,
            "timestamp": _now_ms(),
            "runId": _active_run_id,
        },
    )
    _emit_log("▸ Initializing step-by-step handshake flow...", "info")
    if auto_advance:
        _emit_log("  Running full flow with automatic continuation", "info")
    else:
        _emit_log("  Click next step node to continue", "info")
    _run_next_step_for_client()


@socketio.on("continue_step_flow")
def on_continue_step_flow(payload: Optional[Dict[str, Any]] = None) -> None:
    if _active_session:
        _active_session.client_sid = request.sid
    expected_run_id = (payload or {}).get("runId")
    if _active_run_id and expected_run_id and expected_run_id != _active_run_id:
        emit(
            "step_flow_error",
            {
                "message": "Stale run context. Refreshing state.",
                "runId": _active_run_id,
                "timestamp": _now_ms(),
            },
        )
        _emit_state_snapshot()
        return
    # If the current step is interactive and we're paused AT it (not past it),
    # complete the interactive step rather than starting the next one.
    step_id = STEP_ORDER[_active_session.step_index] if _active_session.step_index < len(STEP_ORDER) else None
    if step_id and step_id in INTERACTIVE_STEPS and _active_session.status == "paused":
        _complete_interactive_step()
    else:
        _run_next_step_for_client()


@socketio.on("reset_step_flow")
def on_reset_step_flow(payload: Optional[Dict[str, Any]] = None) -> None:
    if _active_session:
        _active_session.client_sid = request.sid
    requested_run_id = (payload or {}).get("runId")
    if _active_run_id and requested_run_id and requested_run_id != _active_run_id:
        _emit_state_snapshot()
        return

    _reset_active_run()


@socketio.on("get_step_flow_state")
def on_get_step_flow_state() -> None:
    if _active_session:
        _active_session.client_sid = request.sid
    _emit_state_snapshot(sid_override=request.sid)


if __name__ == "__main__":
    print("Starting step flow server on http://127.0.0.1:5002")
    socketio.run(app, host="127.0.0.1", port=5002, allow_unsafe_werkzeug=True)
