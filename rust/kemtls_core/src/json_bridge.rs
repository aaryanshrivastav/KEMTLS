use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};

fn py_to_json(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }

    if obj.is_instance_of::<PyBool>() {
        let v = obj.extract::<bool>()?;
        return Ok(Value::Bool(v));
    }

    if obj.is_instance_of::<PyInt>() {
        if let Ok(v) = obj.extract::<i64>() {
            return Ok(Value::Number(Number::from(v)));
        }
        if let Ok(v) = obj.extract::<u64>() {
            return Ok(Value::Number(Number::from(v)));
        }
        return Err(PyValueError::new_err("integer value out of supported JSON range"));
    }

    if obj.is_instance_of::<PyFloat>() {
        let v = obj.extract::<f64>()?;
        if !v.is_finite() {
            return Err(PyValueError::new_err(
                "Out of range float values are not JSON compliant",
            ));
        }
        let number = Number::from_f64(v)
            .ok_or_else(|| PyValueError::new_err("Out of range float values are not JSON compliant"))?;
        return Ok(Value::Number(number));
    }

    if let Ok(s) = obj.downcast::<PyString>() {
        return Ok(Value::String(s.to_string_lossy().into_owned()));
    }

    if let Ok(b) = obj.downcast::<PyBytes>() {
        return Ok(Value::String(URL_SAFE_NO_PAD.encode(b.as_bytes())));
    }

    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut keys: Vec<String> = Vec::with_capacity(dict.len());
        for (k, _) in dict.iter() {
            if let Ok(s) = k.downcast::<PyString>() {
                keys.push(s.to_string_lossy().into_owned());
            } else {
                return Err(PyTypeError::new_err("JSON object keys must be strings"));
            }
        }
        keys.sort_unstable();

        let mut map = Map::with_capacity(keys.len());
        for key in keys {
            let value_obj = dict
                .get_item(key.as_str())?
                .ok_or_else(|| PyValueError::new_err("missing dictionary key during encoding"))?;
            map.insert(key, py_to_json(&value_obj)?);
        }
        return Ok(Value::Object(map));
    }

    if let Ok(list) = obj.downcast::<PyList>() {
        let mut values = Vec::with_capacity(list.len());
        for item in list.iter() {
            values.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(values));
    }

    if let Ok(tuple) = obj.downcast::<PyTuple>() {
        let mut values = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            values.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(values));
    }

    Err(PyTypeError::new_err(
        "Object of unsupported type is not JSON serializable",
    ))
}

pub(crate) fn json_to_py(py: Python<'_>, value: Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(v) => Ok(v.into_py(py)),
        Value::Number(v) => {
            if let Some(i) = v.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(u) = v.as_u64() {
                Ok(u.into_py(py))
            } else if let Some(f) = v.as_f64() {
                Ok(f.into_py(py))
            } else {
                Err(PyValueError::new_err("Invalid JSON number"))
            }
        }
        Value::String(v) => Ok(v.into_py(py)),
        Value::Array(values) => {
            let mut py_values = Vec::with_capacity(values.len());
            for item in values {
                py_values.push(json_to_py(py, item)?);
            }
            Ok(PyList::new_bound(py, py_values).into_py(py))
        }
        Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

#[pyfunction]
pub fn canonical_json_encode(py: Python<'_>, obj: &Bound<'_, PyDict>) -> PyResult<Py<PyBytes>> {
    let value = py_to_json(obj.as_any())?;
    let encoded = serde_json::to_vec(&value)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize message: {e}")))?;
    Ok(PyBytes::new_bound(py, &encoded).into())
}

#[pyfunction]
pub fn canonical_json_decode(py: Python<'_>, data: &[u8]) -> PyResult<PyObject> {
    let value: Value = serde_json::from_slice(data)
        .map_err(|e| PyValueError::new_err(format!("Invalid JSON data: {e}")))?;
    match value {
        Value::Object(_) => json_to_py(py, value),
        _ => Err(PyValueError::new_err("Invalid JSON data: root must be an object")),
    }
}
