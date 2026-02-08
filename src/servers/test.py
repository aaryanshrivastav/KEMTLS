"""Virtual sandbox test for servers package.

Runs auth_server and resource_server with dummy replacements for external
crypto/oidc/pop/utils dependencies. Prints each function execution to CLI.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types


CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.dirname(CURRENT_DIR)

# Avoid stdlib `token` shadowing when running as a script from src/servers
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


def _install_fake_dependencies() -> None:
    # crypto.kyber_kem
    crypto_pkg = types.ModuleType("crypto")
    crypto_pkg.__path__ = [os.path.join(SRC_DIR, "crypto")]
    sys.modules["crypto"] = crypto_pkg

    kyber_kem = types.ModuleType("crypto.kyber_kem")

    class KyberKEM:
        def generate_keypair(self):
            return b"pk", b"sk"

    kyber_kem.KyberKEM = KyberKEM
    sys.modules["crypto.kyber_kem"] = kyber_kem

    # crypto.dilithium_sig
    dilithium_sig = types.ModuleType("crypto.dilithium_sig")

    class DilithiumSignature:
        def generate_keypair(self):
            return b"issuer_pk", b"issuer_sk"

    dilithium_sig.DilithiumSignature = DilithiumSignature
    sys.modules["crypto.dilithium_sig"] = dilithium_sig

    # kemtls.session
    kemtls_pkg = types.ModuleType("kemtls")
    kemtls_pkg.__path__ = [os.path.join(SRC_DIR, "kemtls")]
    sys.modules["kemtls"] = kemtls_pkg

    kemtls_session = types.ModuleType("kemtls.session")

    class KEMTLSSession:
        pass

    kemtls_session.KEMTLSSession = KEMTLSSession
    sys.modules["kemtls.session"] = kemtls_session

    # oidc package and endpoints
    oidc_pkg = types.ModuleType("oidc")
    oidc_pkg.__path__ = [os.path.join(SRC_DIR, "oidc")]
    sys.modules["oidc"] = oidc_pkg

    authorization = types.ModuleType("oidc.authorization")

    class AuthorizationEndpoint:
        def handle_authorize_request(self, **kwargs):
            return {"code": "dummy-code", "state": kwargs.get("state")}

    authorization.AuthorizationEndpoint = AuthorizationEndpoint
    sys.modules["oidc.authorization"] = authorization

    token = types.ModuleType("oidc.token")

    class TokenEndpoint:
        def __init__(self, issuer_url, issuer_sk, issuer_pk):
            self.issuer_url = issuer_url

        def handle_token_request(self, **kwargs):
            return {"access_token": "dummy", "token_type": "Bearer"}

    token.TokenEndpoint = TokenEndpoint
    sys.modules["oidc.token"] = token

    discovery = types.ModuleType("oidc.discovery")

    class DiscoveryEndpoint:
        def __init__(self, issuer_url: str):
            self.issuer_url = issuer_url

        def get_configuration(self):
            return {"issuer": self.issuer_url, "kemtls_supported": True}

    discovery.DiscoveryEndpoint = DiscoveryEndpoint
    sys.modules["oidc.discovery"] = discovery

    jwt_handler = types.ModuleType("oidc.jwt_handler")

    class PQJWT:
        def verify_id_token(self, token, issuer_pk):
            return {"cnf": {"jwk": "dummy"}}

    jwt_handler.PQJWT = PQJWT
    sys.modules["oidc.jwt_handler"] = jwt_handler

    # pop.server
    pop_pkg = types.ModuleType("pop")
    pop_pkg.__path__ = [os.path.join(SRC_DIR, "pop")]
    sys.modules["pop"] = pop_pkg

    pop_server = types.ModuleType("pop.server")

    class ProofOfPossession:
        def generate_challenge(self):
            return "challenge"

    pop_server.ProofOfPossession = ProofOfPossession
    sys.modules["pop.server"] = pop_server

    # utils.helpers
    utils_pkg = types.ModuleType("utils")
    utils_pkg.__path__ = [os.path.join(SRC_DIR, "utils")]
    sys.modules["utils"] = utils_pkg

    utils_helpers = types.ModuleType("utils.helpers")

    def is_expired(*args, **kwargs):
        return False

    utils_helpers.is_expired = is_expired
    sys.modules["utils.helpers"] = utils_helpers


def run_sandbox() -> None:
    print("[sandbox] installing fake dependencies")
    _install_fake_dependencies()

    print("[sandbox] loading server modules")
    auth_server = _load_module(
        "servers.auth_server", os.path.join(CURRENT_DIR, "auth_server.py")
    )
    resource_server = _load_module(
        "servers.resource_server", os.path.join(CURRENT_DIR, "resource_server.py")
    )

    print("[auth_server] init AuthorizationServer")
    auth = auth_server.AuthorizationServer("http://localhost:5000")
    client = auth.app.test_client()

    print("[auth_server] GET /.well-known/openid-configuration")
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200

    print("[auth_server] GET /authorize")
    resp = client.get(
        "/authorize",
        query_string={
            "client_id": "client123",
            "redirect_uri": "https://client/cb",
            "scope": "openid",
            "state": "state",
            "nonce": "nonce",
        },
    )
    assert resp.status_code == 200

    print("[auth_server] POST /token")
    resp = client.post("/token", json={"code": "dummy-code"})
    assert resp.status_code == 200

    print("[resource_server] init ResourceServer")
    rs = resource_server.ResourceServer(b"issuer_pk")
    rs_client = rs.app.test_client()

    print("[resource_server] GET /api/userinfo unauthorized")
    resp = rs_client.get("/api/userinfo")
    assert resp.status_code == 401

    print("[resource_server] GET /api/userinfo with bearer")
    resp = rs_client.get(
        "/api/userinfo", headers={"Authorization": "Bearer dummy"}
    )
    assert resp.status_code == 200

    print("✅ servers sandbox checks passed")


if __name__ == "__main__":
    run_sandbox()
