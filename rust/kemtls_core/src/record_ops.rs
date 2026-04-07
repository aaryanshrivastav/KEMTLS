use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
pub fn frame_record(py: Python<'_>, seq: u64, payload: &[u8]) -> PyResult<Py<PyBytes>> {
    let length: u32 = payload
        .len()
        .try_into()
        .map_err(|_| PyValueError::new_err("payload too large"))?;

    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(PyBytes::new_bound(py, &out).into())
}

#[pyfunction]
pub fn parse_record(py: Python<'_>, data: &[u8]) -> PyResult<(u64, Py<PyBytes>)> {
    if data.len() < 12 {
        return Err(PyValueError::new_err("record too short"));
    }

    let seq = u64::from_be_bytes(data[0..8].try_into().expect("slice length checked"));
    let length = u32::from_be_bytes(data[8..12].try_into().expect("slice length checked")) as usize;
    let expected = 12 + length;
    if data.len() != expected {
        return Err(PyValueError::new_err("invalid record length"));
    }

    let payload = PyBytes::new_bound(py, &data[12..]);
    Ok((seq, payload.into()))
}
