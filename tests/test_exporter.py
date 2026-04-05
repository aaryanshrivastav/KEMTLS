from kemtls.exporter import (
    derive_exporter_secret,
    derive_refresh_binding_id,
    derive_session_binding_id,
)


def test_exporter_secret_is_deterministic_and_session_specific():
    app_secret = b"A" * 32
    transcript_one = b"\x01" * 32
    transcript_two = b"\x02" * 32

    exporter_one = derive_exporter_secret(app_secret, transcript_one)
    exporter_one_again = derive_exporter_secret(app_secret, transcript_one)
    exporter_two = derive_exporter_secret(app_secret, transcript_two)

    assert exporter_one == exporter_one_again
    assert exporter_one != exporter_two


def test_binding_ids_are_context_separated():
    exporter_secret = b"E" * 32

    session_binding = derive_session_binding_id(exporter_secret, as_base64=False)
    refresh_binding = derive_refresh_binding_id(exporter_secret, as_base64=False)

    assert session_binding != refresh_binding
    assert len(session_binding) == 32
    assert len(refresh_binding) == 32


def test_binding_ids_can_be_returned_as_base64url():
    exporter_secret = b"E" * 32

    session_binding = derive_session_binding_id(exporter_secret)
    refresh_binding = derive_refresh_binding_id(exporter_secret)

    assert isinstance(session_binding, str)
    assert isinstance(refresh_binding, str)
    assert session_binding
    assert refresh_binding
