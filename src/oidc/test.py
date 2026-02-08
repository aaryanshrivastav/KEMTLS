"""Virtual sandbox test for OIDC package.

Uses dummy values and a fake JWT handler to avoid dependencies on crypto/utils tests.
Run directly to validate basic behavior of all OIDC modules.
"""

import os
import sys
import importlib.util
import types
from typing import Any, Dict


CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.dirname(CURRENT_DIR)

# Avoid stdlib `token` shadowing when running as a script from src/oidc
if sys.path and sys.path[0] == CURRENT_DIR:
    sys.path.pop(0)

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def _load_module(module_name: str, file_path: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class _FakeJWT:
    """Minimal JWT handler replacement for sandbox testing."""

    def __init__(self):
        self.last_claims: Dict[str, Any] | None = None

    def create_id_token(
        self,
        claims: Dict[str, Any],
        issuer_sk: bytes,
        issuer_pk: bytes,
        client_ephemeral_pk: bytes | None = None,
        session_key: bytes | None = None,
        session_id: str | None = None,
    ) -> str:
        self.last_claims = dict(claims)
        if client_ephemeral_pk:
            self.last_claims["_pop_bound"] = True
        if session_id:
            self.last_claims["_session_id"] = session_id
        return "dummy.jwt.token"


def _prepare_oidc_modules():
    oidc_dir = CURRENT_DIR

    oidc_pkg = types.ModuleType("oidc")
    oidc_pkg.__path__ = [oidc_dir]
    sys.modules["oidc"] = oidc_pkg

    jwt_handler = types.ModuleType("oidc.jwt_handler")

    class PQJWT:  # noqa: N801 - keep class name to match production
        def __init__(self):
            self._impl = _FakeJWT()

        def create_id_token(self, *args, **kwargs):
            return self._impl.create_id_token(*args, **kwargs)

        @property
        def last_claims(self):
            return self._impl.last_claims

    jwt_handler.PQJWT = PQJWT
    sys.modules["oidc.jwt_handler"] = jwt_handler

    authorization = _load_module(
        "oidc.authorization", os.path.join(oidc_dir, "authorization.py")
    )
    claims = _load_module("oidc.claims", os.path.join(oidc_dir, "claims.py"))
    discovery = _load_module(
        "oidc.discovery", os.path.join(oidc_dir, "discovery.py")
    )
    token = _load_module("oidc.token", os.path.join(oidc_dir, "token.py"))

    return authorization, claims, discovery, token


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_sandbox() -> None:
    """Run sandbox checks for all OIDC modules with dummy values."""

    print("[sandbox] loading oidc modules")
    authorization_mod, claims_mod, discovery_mod, token_mod = _prepare_oidc_modules()
    AuthorizationEndpoint = authorization_mod.AuthorizationEndpoint
    ClaimsProcessor = claims_mod.ClaimsProcessor
    DiscoveryEndpoint = discovery_mod.DiscoveryEndpoint
    TokenEndpoint = token_mod.TokenEndpoint

    # Authorization endpoint
    print("[authorization] init AuthorizationEndpoint")
    auth = AuthorizationEndpoint()
    print("[authorization] handle_authorize_request: invalid_request")
    bad = auth.handle_authorize_request("", "https://client/cb", "openid", "s")
    _assert(bad == {"error": "invalid_request"}, "invalid_request expected")

    print("[authorization] handle_authorize_request: auth_required")
    auth_required = auth.handle_authorize_request(
        "client123", "https://client/cb", "openid", "s"
    )
    _assert(auth_required == {"auth_required": True}, "auth_required expected")

    print("[authorization] handle_authorize_request: issue code")
    ok = auth.handle_authorize_request(
        "client123",
        "https://client/cb",
        "openid profile email",
        "s",
        nonce="n",
        user_id="alice",
    )
    _assert("code" in ok, "authorization code missing")
    print("[authorization] validate_code")
    code_data = auth.validate_code(ok["code"], "client123", "https://client/cb")
    _assert(code_data is not None, "code validation failed")

    # Claims processing
    print("[claims] get_user_claims")
    claims = ClaimsProcessor().get_user_claims("alice", ["profile", "email"])
    _assert(claims["sub"] == "alice", "claims sub mismatch")
    _assert(claims["name"] == "Alice", "claims name mismatch")
    _assert(claims["email"] == "alice@example.com", "claims email mismatch")

    # Discovery endpoint
    print("[discovery] init DiscoveryEndpoint")
    issuer = "https://issuer.example"
    discovery = DiscoveryEndpoint(issuer)
    print("[discovery] get_configuration")
    config = discovery.get_configuration()
    _assert(config["issuer"] == issuer, "discovery issuer mismatch")
    _assert(config["authorization_endpoint"].endswith("/authorize"), "missing auth endpoint")

    # Token endpoint using fake JWT handler
    print("[token] init TokenEndpoint")
    token_ep = TokenEndpoint(issuer_url=issuer, issuer_sk=b"sk", issuer_pk=b"pk")

    print("[token] handle_token_request")
    token_response = token_ep.handle_token_request(
        grant_type="authorization_code",
        code="dummy-code",
        code_data=code_data,
        client_ephemeral_pk=b"client-pk",
        session_id="session-1",
        session_key=b"session-key",
    )

    _assert(token_response["token_type"] == "Bearer", "token_type mismatch")
    _assert(token_response["id_token"] == "dummy.jwt.token", "id_token mismatch")
    _assert(token_response["access_token"] == "dummy.jwt.token", "access_token mismatch")
    _assert("profile" in token_response["scope"], "scope missing profile")
    _assert("email" in token_response["scope"], "scope missing email")

    print("[token] validate generated claims (fake jwt handler)")
    fake_claims = token_ep.jwt_handler.last_claims or {}
    _assert(fake_claims.get("sub") == "alice", "token claims sub mismatch")
    _assert(fake_claims.get("aud") == "client123", "token claims aud mismatch")
    _assert(fake_claims.get("nonce") == "n", "token claims nonce mismatch")

    print("✅ OIDC sandbox checks passed")


if __name__ == "__main__":
    run_sandbox()
