import pytest

from kemtls.pdk import PDKTrustStore


def test_pdk_trust_store_lookup_and_resolution():
    store = PDKTrustStore()
    alice_key = b"A" * 1184
    store.add_entry("alice-key-1", "alice", alice_key, {"env": "dev"})

    by_id = store.get_entry_by_id("alice-key-1")
    by_identity = store.get_entry_by_identity("alice")
    resolved = store.resolve_expected_identity("alice", "alice-key-1")

    assert by_id["identity"] == "alice"
    assert by_identity["key_id"] == "alice-key-1"
    assert resolved["ml_kem_public_key"] == alice_key
    assert resolved["metadata"]["env"] == "dev"


def test_pdk_rejects_unknown_key_and_identity_mismatch():
    store = PDKTrustStore()
    store.add_entry("alice-key-1", "alice", b"A" * 1184)

    with pytest.raises(KeyError, match="not found"):
        store.get_entry_by_id("missing")

    with pytest.raises(ValueError, match="Identity mismatch"):
        store.resolve_expected_identity("bob", "alice-key-1")


def test_pdk_rejects_ambiguous_or_missing_identity_lookups():
    store = PDKTrustStore()
    store.add_entry("alice-key-1", "alice", b"A" * 1184)
    store.add_entry("alice-key-2", "alice", b"B" * 1184)

    with pytest.raises(ValueError, match="Ambiguous identity"):
        store.get_entry_by_identity("alice")

    with pytest.raises(ValueError, match="No trusted keys found"):
        store.get_entry_by_identity("bob")
