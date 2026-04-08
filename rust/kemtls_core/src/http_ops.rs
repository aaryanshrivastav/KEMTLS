use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use serde_json::Value;
use std::str;

use crate::json_bridge::json_to_py;

#[pyfunction]
pub fn parse_http_request(py: Python<'_>, raw_data: &[u8]) -> PyResult<PyObject> {
    // Fast path: parse request-line and headers in-place without materializing split vectors.
    let request_line_end = raw_data
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(raw_data.len());
    let request_line = &raw_data[..request_line_end];

    let parts: Vec<&[u8]> = request_line.split(|b| *b == b' ').collect();
    if parts.len() != 3 {
        return Err(PyValueError::new_err("Invalid HTTP request line"));
    }
    let method = parts[0];
    let path = parts[1];
    let version = parts[2];

    let method_str = str::from_utf8(method)
        .map_err(|_| PyValueError::new_err("Invalid HTTP method encoding"))?;
    let path_str = str::from_utf8(path)
        .map_err(|_| PyValueError::new_err("Invalid HTTP path encoding"))?;
    let version_str = str::from_utf8(version)
        .map_err(|_| PyValueError::new_err("Invalid HTTP version encoding"))?;

    let headers = PyDict::new_bound(py);
    let header_block_start = if request_line_end + 2 <= raw_data.len() {
        request_line_end + 2
    } else {
        raw_data.len()
    };
    let body_start = raw_data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .unwrap_or(raw_data.len());

    let mut cursor = header_block_start;
    while cursor < body_start {
        let next_rel = raw_data[cursor..body_start]
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(body_start - cursor);
        let line_end = cursor + next_rel;
        let line = &raw_data[cursor..line_end];
        if line.is_empty() {
            break;
        }
        if let Some(idx) = line.iter().position(|b| *b == b':') {
            let key = str::from_utf8(&line[..idx])
                .map_err(|_| PyValueError::new_err("Invalid HTTP header encoding"))?
                .trim()
                .to_ascii_lowercase();
            let value = str::from_utf8(&line[idx + 1..])
                .map_err(|_| PyValueError::new_err("Invalid HTTP header encoding"))?
                .trim()
                .to_string();
            headers.set_item(key, value)?;
        }
        cursor = line_end.saturating_add(2);
    }

    let body = PyBytes::new_bound(py, &raw_data[body_start..]);

    let result = PyDict::new_bound(py);
    result.set_item("method", method_str)?;
    result.set_item("path", path_str)?;
    result.set_item("version", version_str)?;
    result.set_item("headers", headers)?;
    result.set_item("body", body)?;
    Ok(result.into_py(py))
}

#[pyfunction]
pub fn parse_http_response(py: Python<'_>, raw_data: &[u8]) -> PyResult<PyObject> {
    let header_end = raw_data.windows(4).position(|w| w == b"\r\n\r\n");
    let (header_part, body) = if let Some(pos) = header_end {
        (&raw_data[..pos], &raw_data[pos + 4..])
    } else {
        (raw_data, &[][..])
    };

    let header_text = str::from_utf8(header_part)
        .map_err(|e| PyValueError::new_err(format!("header decode error: {e}")))?;
    let header_lines: Vec<&str> = header_text.split("\r\n").collect();
    if header_lines.is_empty() || header_lines[0].is_empty() {
        return Err(PyValueError::new_err("missing status line"));
    }

    let mut status_parts = header_lines[0].splitn(3, ' ');
    let _http_version = status_parts
        .next()
        .ok_or_else(|| PyValueError::new_err("invalid status line"))?;
    let code = status_parts
        .next()
        .ok_or_else(|| PyValueError::new_err("invalid status line"))?;
    let status_code: i64 = code
        .parse()
        .map_err(|e| PyValueError::new_err(format!("invalid status code: {e}")))?;
    let status_text = status_parts.next().unwrap_or("");

    let headers = PyDict::new_bound(py);
    for line in header_lines.iter().skip(1) {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.set_item(key.trim(), value.trim())?;
        }
    }

    let content_type = if let Ok(Some(v)) = headers.get_item("Content-Type") {
        v.extract::<String>()?.to_ascii_lowercase()
    } else if let Ok(Some(v)) = headers.get_item("content-type") {
        v.extract::<String>()?.to_ascii_lowercase()
    } else {
        String::new()
    };

    let body_obj = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<Value>(body) {
            Ok(value) => json_to_py(py, value)?,
            Err(_) => PyBytes::new_bound(py, body).into_py(py),
        }
    } else if content_type.starts_with("text/") {
        match str::from_utf8(body) {
            Ok(text) => text.into_py(py),
            Err(_) => PyBytes::new_bound(py, body).into_py(py),
        }
    } else {
        PyBytes::new_bound(py, body).into_py(py)
    };

    let result = PyDict::new_bound(py);
    result.set_item("status", status_code)?;
    result.set_item("status_text", status_text)?;
    result.set_item("headers", headers)?;
    result.set_item("body", body_obj)?;
    Ok(result.into_py(py))
}
