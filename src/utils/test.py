"""Virtual sandbox test for utils package.

Runs utils modules with dummy replacements for external randomness/time.
Prints each function execution to CLI.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types


CURRENT_DIR = os.path.dirname(__file__)
SRC_DIR = os.path.dirname(CURRENT_DIR)

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
    # Deterministic secrets / os.urandom / time.time
    fake_secrets = types.ModuleType("secrets")

    def choice(seq):
        return seq[0]

    fake_secrets.choice = choice
    sys.modules["secrets"] = fake_secrets

    fake_time = types.ModuleType("time")

    def time_fn():
        return 1700000000.0

    fake_time.time = time_fn
    sys.modules["time"] = fake_time

    # Wrap os to keep real path utilities but deterministic urandom
    import os as _real_os

    fake_os = types.ModuleType("os")
    fake_os.__dict__.update(_real_os.__dict__)

    def urandom(n: int) -> bytes:
        return b"\x01" * n

    fake_os.urandom = urandom
    sys.modules["os"] = fake_os


def run_sandbox() -> None:
    print("[sandbox] installing fake dependencies")
    _install_fake_dependencies()

    print("[sandbox] loading utils modules")
    encoding = _load_module("utils.encoding", os.path.join(CURRENT_DIR, "encoding.py"))
    helpers = _load_module("utils.helpers", os.path.join(CURRENT_DIR, "helpers.py"))
    serialization = _load_module(
        "utils.serialization", os.path.join(CURRENT_DIR, "serialization.py")
    )

    print("[encoding] base64url_encode / base64url_decode")
    encoded = encoding.base64url_encode(b"hello")
    decoded = encoding.base64url_decode(encoded)
    assert decoded == b"hello"

    print("[helpers] generate_random_string")
    rand_str = helpers.generate_random_string(8)
    assert len(rand_str) == 8

    print("[helpers] generate_random_bytes")
    rand_bytes = helpers.generate_random_bytes(8)
    assert rand_bytes == b"\x01" * 8

    print("[helpers] get_timestamp")
    ts = helpers.get_timestamp()
    assert ts == 1700000000

    print("[helpers] is_expired")
    assert helpers.is_expired(1699999999, 1700000000) is True
    assert helpers.is_expired(1700000001, 1700000000) is False

    print("[helpers] create_jwk_from_dilithium_pubkey / extract_pubkey_from_jwk")
    jwk = helpers.create_jwk_from_dilithium_pubkey(b"\x02" * 1952, "kid")
    recovered = helpers.extract_pubkey_from_jwk(jwk)
    assert recovered == b"\x02" * 1952

    print("[helpers] format_token_for_display")
    formatted = helpers.format_token_for_display("a" * 100, 20)
    assert len(formatted) == 20

    print("[helpers] validate_session_id")
    assert helpers.validate_session_id("valid-session_123") is True
    assert helpers.validate_session_id("bad!") is False

    print("[serialization] serialize_message / deserialize_message")
    message = {"type": "test", "data": "hello"}
    data = serialization.serialize_message(message)
    recovered_msg = serialization.deserialize_message(data)
    assert recovered_msg == message

    print("✅ utils sandbox checks passed")


if __name__ == "__main__":
    run_sandbox()
