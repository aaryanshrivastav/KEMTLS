"""Post-quantum crypto primitives for the updated KEMTLS architecture."""

from __future__ import annotations

from importlib import import_module


_LAZY_EXPORTS = {
    "HASH_LEN": ("crypto.key_schedule", "HASH_LEN"),
    "KEY_SIZE": ("crypto.aead", "KEY_SIZE"),
    "MLDSA65": ("crypto.ml_dsa", "MLDSA65"),
    "MLKEM768": ("crypto.ml_kem", "MLKEM768"),
    "NONCE_SIZE": ("crypto.aead", "NONCE_SIZE"),
    "TAG_SIZE": ("crypto.aead", "TAG_SIZE"),
    "compute_transcript_hash": ("crypto.key_schedule", "compute_transcript_hash"),
    "derive_application_traffic_secrets": (
        "crypto.key_schedule",
        "derive_application_traffic_secrets",
    ),
    "derive_finished_keys": ("crypto.key_schedule", "derive_finished_keys"),
    "derive_handshake_secret": ("crypto.key_schedule", "derive_handshake_secret"),
    "derive_handshake_traffic_secrets": (
        "crypto.key_schedule",
        "derive_handshake_traffic_secrets",
    ),
    "hkdf_expand_label": ("crypto.key_schedule", "hkdf_expand_label"),
    "hkdf_extract": ("crypto.key_schedule", "hkdf_extract"),
    "open_": ("crypto.aead", "open_"),
    "seal": ("crypto.aead", "seal"),
    "xor_iv_with_seq": ("crypto.aead", "xor_iv_with_seq"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str):
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module 'crypto' has no attribute {name!r}")

    module_name, attribute_name = _LAZY_EXPORTS[name]
    module = import_module(module_name)
    return getattr(module, attribute_name)
