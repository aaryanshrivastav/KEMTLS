import rust_ext

from crypto.key_schedule import compute_transcript_hash
from kemtls.handshake import (
    _encode_client_hello,
    _encode_client_key_exchange,
    _encode_finished_message,
)


def _run_with_python_fallback(monkeypatch, fn, *args):
    original_core = rust_ext._core
    original_flag = rust_ext.HAS_RUST_BACKEND
    monkeypatch.setattr(rust_ext, "_core", None)
    monkeypatch.setattr(rust_ext, "HAS_RUST_BACKEND", False)
    try:
        return fn(*args)
    finally:
        monkeypatch.setattr(rust_ext, "_core", original_core)
        monkeypatch.setattr(rust_ext, "HAS_RUST_BACKEND", original_flag)


def test_client_hello_encoding_matches_python_fallback(monkeypatch):
    modes = ["baseline", "pdk"]
    rust_bytes = _encode_client_hello("r" * 32, "auth-server", modes)
    py_bytes = _run_with_python_fallback(
        monkeypatch,
        _encode_client_hello,
        "r" * 32,
        "auth-server",
        modes,
    )
    assert rust_bytes == py_bytes


def test_client_key_exchange_encoding_matches_python_fallback(monkeypatch):
    ct_eph = b"\x01\x02\x03" * 10
    ct_lt = b"\x04\x05\x06" * 10
    rust_bytes = _encode_client_key_exchange(ct_eph, ct_lt)
    py_bytes = _run_with_python_fallback(monkeypatch, _encode_client_key_exchange, ct_eph, ct_lt)
    assert rust_bytes == py_bytes


def test_finished_encoding_matches_python_fallback(monkeypatch):
    mac = b"\x0a" * 32

    rust_server = _encode_finished_message("ServerFinished", mac)
    py_server = _run_with_python_fallback(
        monkeypatch,
        _encode_finished_message,
        "ServerFinished",
        mac,
    )
    rust_client = _encode_finished_message("ClientFinished", mac)
    py_client = _run_with_python_fallback(
        monkeypatch,
        _encode_finished_message,
        "ClientFinished",
        mac,
    )

    assert rust_server == py_server
    assert rust_client == py_client


def test_transcript_hash_many_matches_python_fallback(monkeypatch):
    messages = [b"ClientHello", b"ServerHello", b"ClientKeyExchange", b"ServerFinished"]

    rust_digest = compute_transcript_hash(messages)
    py_digest = _run_with_python_fallback(monkeypatch, compute_transcript_hash, messages)

    assert rust_digest == py_digest
