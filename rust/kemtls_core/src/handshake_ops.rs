use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
pub fn handshake_client_hello(
    py: Python<'_>,
    client_random: &str,
    expected_identity: &str,
    modes: Vec<String>,
) -> PyResult<Py<PyBytes>> {
    let random_json = serde_json::to_string(client_random)
        .map_err(|e| PyValueError::new_err(format!("invalid random field: {e}")))?;
    let expected_identity_json = serde_json::to_string(expected_identity)
        .map_err(|e| PyValueError::new_err(format!("invalid expected_identity field: {e}")))?;
    let modes_json = serde_json::to_string(&modes)
        .map_err(|e| PyValueError::new_err(format!("invalid modes field: {e}")))?;

    let encoded = format!(
        "{{\"expected_identity\":{expected_identity_json},\"modes\":{modes_json},\"random\":{random_json},\"type\":\"ClientHello\",\"version\":\"KEMTLS/1.0\"}}"
    );
    Ok(PyBytes::new_bound(py, encoded.as_bytes()).into())
}

#[pyfunction]
pub fn handshake_client_key_exchange(
    py: Python<'_>,
    ct_ephemeral: &[u8],
    ct_longterm: &[u8],
) -> Py<PyBytes> {
    let ct_ephemeral_b64 = URL_SAFE_NO_PAD.encode(ct_ephemeral);
    let ct_longterm_b64 = URL_SAFE_NO_PAD.encode(ct_longterm);

    let encoded = format!(
        "{{\"ct_ephemeral\":\"{ct_ephemeral_b64}\",\"ct_longterm\":\"{ct_longterm_b64}\",\"type\":\"ClientKeyExchange\"}}"
    );
    PyBytes::new_bound(py, encoded.as_bytes()).into()
}

#[pyfunction]
pub fn handshake_finished(py: Python<'_>, message_type: &str, mac: &[u8]) -> PyResult<Py<PyBytes>> {
    if message_type != "ClientFinished" && message_type != "ServerFinished" {
        return Err(PyValueError::new_err(
            "message_type must be ClientFinished or ServerFinished",
        ));
    }

    let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
    let encoded = format!("{{\"mac\":\"{mac_b64}\",\"type\":\"{message_type}\"}}");
    Ok(PyBytes::new_bound(py, encoded.as_bytes()).into())
}
