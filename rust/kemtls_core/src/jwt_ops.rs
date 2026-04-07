use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
pub fn split_jwt(token: &str) -> PyResult<(String, String, String)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(PyValueError::new_err("invalid JWT format"));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

#[pyfunction]
pub fn jwt_signing_input(py: Python<'_>, header_b64: &str, payload_b64: &str) -> Py<PyBytes> {
    let s = format!("{header_b64}.{payload_b64}");
    PyBytes::new_bound(py, s.as_bytes()).into()
}
