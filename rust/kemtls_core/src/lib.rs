use pyo3::prelude::*;
mod crypto_ops;
mod handshake_ops;
mod http_ops;
mod json_bridge;
mod jwt_ops;
mod record_ops;

#[pymodule]
fn kemtls_core(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(crypto_ops::build_profile, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::xor_iv_with_seq, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::aead_seal, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::aead_open, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::hkdf_extract, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::hkdf_expand, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::transcript_hash, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::transcript_hash_many, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::sha256_digest, m)?)?;
    m.add_function(wrap_pyfunction!(crypto_ops::sha256_hex, m)?)?;

    m.add_function(wrap_pyfunction!(json_bridge::canonical_json_encode, m)?)?;
    m.add_function(wrap_pyfunction!(json_bridge::canonical_json_decode, m)?)?;

    m.add_function(wrap_pyfunction!(record_ops::frame_record, m)?)?;
    m.add_function(wrap_pyfunction!(record_ops::parse_record, m)?)?;

    m.add_function(wrap_pyfunction!(http_ops::parse_http_request, m)?)?;
    m.add_function(wrap_pyfunction!(http_ops::parse_http_response, m)?)?;

    m.add_function(wrap_pyfunction!(jwt_ops::split_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(jwt_ops::jwt_signing_input, m)?)?;

    m.add_function(wrap_pyfunction!(handshake_ops::handshake_client_hello, m)?)?;
    m.add_function(wrap_pyfunction!(handshake_ops::handshake_client_key_exchange, m)?)?;
    m.add_function(wrap_pyfunction!(handshake_ops::handshake_finished, m)?)?;
    Ok(())
}

