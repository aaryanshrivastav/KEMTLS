"""Virtual sandbox test for client package.

Runs client modules with dummy replacements for external dependencies.
Prints each function execution to CLI.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types


CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.dirname(CURRENT_DIR)

# Avoid stdlib `token` shadowing when running as a script from src/client
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
    # pop.client
    pop_pkg = types.ModuleType("pop")
    pop_pkg.__path__ = [os.path.join(SRC_DIR, "pop")]
    sys.modules["pop"] = pop_pkg

    pop_client = types.ModuleType("pop.client")

    class PoPClient:
        def __init__(self, client_ephemeral_sk: bytes):
            self.client_ephemeral_sk = client_ephemeral_sk

        def create_pop_proof(self, challenge, id_token):
            return "pop-proof"

    pop_client.PoPClient = PoPClient
    sys.modules["pop.client"] = pop_client

    # oidc.jwt_handler
    oidc_pkg = types.ModuleType("oidc")
    oidc_pkg.__path__ = [os.path.join(SRC_DIR, "oidc")]
    sys.modules["oidc"] = oidc_pkg

    jwt_handler = types.ModuleType("oidc.jwt_handler")

    class PQJWT:
        pass

    jwt_handler.PQJWT = PQJWT
    sys.modules["oidc.jwt_handler"] = jwt_handler

    # utils.helpers
    utils_pkg = types.ModuleType("utils")
    utils_pkg.__path__ = [os.path.join(SRC_DIR, "utils")]
    sys.modules["utils"] = utils_pkg

    utils_helpers = types.ModuleType("utils.helpers")

    def generate_random_string(length: int = 16, charset: str | None = None) -> str:
        return "x" * length

    utils_helpers.generate_random_string = generate_random_string
    sys.modules["utils.helpers"] = utils_helpers

    # kemtls.session
    kemtls_pkg = types.ModuleType("kemtls")
    kemtls_pkg.__path__ = [os.path.join(SRC_DIR, "kemtls")]
    sys.modules["kemtls"] = kemtls_pkg

    kemtls_session = types.ModuleType("kemtls.session")

    class _Handshake:
        client_ephemeral_pk = b"client-pk"
        client_ephemeral_sk = b"client-sk"

        def client_process_server_hello(self, server_hello, server_longterm_pk):
            return {"client_key_exchange": "ok"}, b"client-epk"

    class KEMTLSSession:
        def __init__(self, is_server: bool = False):
            self.handshake = _Handshake()

        def establish_channel(self):
            return KEMTLSChannel()

        def get_session_id(self):
            return "session-1"

    kemtls_session.KEMTLSSession = KEMTLSSession
    sys.modules["kemtls.session"] = kemtls_session

    # kemtls.channel
    kemtls_channel = types.ModuleType("kemtls.channel")

    class KEMTLSChannel:
        def send(self, data: bytes) -> bytes:
            return b"enc:" + data

        def receive(self, encrypted: bytes) -> bytes:
            prefix = b"enc:"
            return encrypted[len(prefix):] if encrypted.startswith(prefix) else encrypted

    kemtls_channel.KEMTLSChannel = KEMTLSChannel
    sys.modules["kemtls.channel"] = kemtls_channel


def run_sandbox() -> None:
    print("[sandbox] installing fake dependencies")
    _install_fake_dependencies()

    print("[sandbox] loading client modules")
    oidc_client = _load_module(
        "client.oidc_client", os.path.join(CURRENT_DIR, "oidc_client.py")
    )
    kemtls_client = _load_module(
        "client.kemtls_client", os.path.join(CURRENT_DIR, "kemtls_client.py")
    )

    print("[oidc_client] init OIDCClient")
    oidc = oidc_client.OIDCClient(
        client_id="client123",
        redirect_uri="https://client/cb",
        auth_server_url="https://issuer.example",
        client_ephemeral_sk=b"sk",
    )

    print("[oidc_client] create_authorization_url")
    url = oidc.create_authorization_url()
    assert "authorize" in url

    print("[oidc_client] exchange_code_for_tokens")
    tokens = oidc.exchange_code_for_tokens("dummy-code")
    assert tokens["token_type"] == "Bearer"

    print("[oidc_client] store_tokens")
    oidc.store_tokens(tokens)
    assert oidc.id_token == "mock_id_token"

    print("[oidc_client] create_pop_proof_for_resource")
    proof = oidc.create_pop_proof_for_resource({"challenge": "x"})
    assert proof == "pop-proof"

    print("[kemtls_client] init KEMTLSClient")
    kem = kemtls_client.KEMTLSClient()

    print("[kemtls_client] perform_handshake")
    ckx = kem.perform_handshake({"server_hello": True}, b"server-pk")
    assert ckx["client_key_exchange"] == "ok"

    print("[kemtls_client] establish_secure_channel")
    channel = kem.establish_secure_channel()
    assert channel is not None

    print("[kemtls_client] send_encrypted / receive_encrypted")
    enc = kem.send_encrypted(b"hello")
    dec = kem.receive_encrypted(enc)
    assert dec == b"hello"

    print("[kemtls_client] get_client_ephemeral_pubkey")
    assert kem.get_client_ephemeral_pubkey() == b"client-pk"

    print("[kemtls_client] get_client_ephemeral_secretkey")
    assert kem.get_client_ephemeral_secretkey() == b"client-sk"

    print("[kemtls_client] get_session_id")
    assert kem.get_session_id() == "session-1"

    print("✅ client sandbox checks passed")


if __name__ == "__main__":
    run_sandbox()
