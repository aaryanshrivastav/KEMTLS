import pytest

import utils
from utils.helpers import (
    DEFAULT_RANDOM_CHARSET,
    format_token_for_display,
    generate_random_bytes,
    generate_random_string,
    get_timestamp,
    is_expired,
    validate_session_id,
)


def test_generate_random_string_defaults_to_url_safe_charset():
    value = generate_random_string(32)

    assert len(value) == 32
    assert all(character in DEFAULT_RANDOM_CHARSET for character in value)


def test_generate_random_string_validates_inputs():
    assert generate_random_string(0) == ""
    assert set(generate_random_string(8, "ab")) <= {"a", "b"}
    with pytest.raises(ValueError):
        generate_random_string(-1)
    with pytest.raises(ValueError):
        generate_random_string(8, "")
    with pytest.raises(TypeError):
        generate_random_string("8")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        generate_random_string(True)  # type: ignore[arg-type]


def test_generate_random_bytes_validates_inputs():
    assert generate_random_bytes(0) == b""
    assert len(generate_random_bytes(8)) == 8
    with pytest.raises(ValueError):
        generate_random_bytes(-1)
    with pytest.raises(TypeError):
        generate_random_bytes("8")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        generate_random_bytes(False)  # type: ignore[arg-type]


def test_get_timestamp_returns_integer():
    assert isinstance(get_timestamp(), int)


def test_is_expired_supports_none_and_validates_types():
    assert is_expired(None) is False
    assert is_expired(10, 10) is True
    assert is_expired(11, 10) is False
    with pytest.raises(TypeError):
        is_expired("10")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        is_expired(10, "10")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        is_expired(True, 10)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        is_expired(10, False)  # type: ignore[arg-type]


def test_format_token_for_display_truncates_and_validates_inputs():
    assert format_token_for_display("short", 10) == "short"
    assert format_token_for_display("", 10) == ""
    assert format_token_for_display("a" * 100, 20) == "aaaaaaaa...aaaaaaaaa"
    with pytest.raises(TypeError):
        format_token_for_display(123, 20)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        format_token_for_display("token", True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        format_token_for_display("token", 6)


def test_validate_session_id_accepts_only_expected_shape():
    assert validate_session_id("a" * 8) is True
    assert validate_session_id("a" * 128) is True
    assert validate_session_id("valid-session_123") is True
    assert validate_session_id("short") is False
    assert validate_session_id("bad!") is False
    assert validate_session_id("x" * 129) is False
    assert validate_session_id(None) is False  # type: ignore[arg-type]


def test_utils_package_exports_only_generic_helpers():
    assert utils.generate_random_string is generate_random_string
    assert utils.generate_random_bytes is generate_random_bytes
    assert utils.get_timestamp is get_timestamp
    assert utils.is_expired is is_expired
    assert utils.format_token_for_display is format_token_for_display
    assert utils.validate_session_id is validate_session_id
    assert not hasattr(utils, "create_jwk_from_dilithium_pubkey")
    assert not hasattr(utils, "extract_pubkey_from_jwk")
