use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use sha2::{Digest, Sha256};

pub const HASH_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[pyfunction]
pub fn hkdf_extract(py: Python<'_>, salt: &[u8], ikm: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt)
        .map_err(|e| PyValueError::new_err(format!("invalid salt: {e}")))?;
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    Ok(PyBytes::new_bound(py, &out).into())
}

#[pyfunction]
pub fn hkdf_expand(py: Python<'_>, prk: &[u8], info: &[u8], length: usize) -> PyResult<Py<PyBytes>> {
    if length > 255 * HASH_LEN {
        return Err(PyValueError::new_err("length exceeds HKDF expand limit"));
    }

    let mut output = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while output.len() < length {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .map_err(|e| PyValueError::new_err(format!("invalid prk: {e}")))?;
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&previous);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| PyValueError::new_err("hkdf expand counter overflow"))?;
    }

    output.truncate(length);
    Ok(PyBytes::new_bound(py, &output).into())
}

#[pyfunction]
pub fn transcript_hash(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    let digest = Sha256::digest(data);
    PyBytes::new_bound(py, &digest).into()
}

#[pyfunction]
pub fn transcript_hash_many(py: Python<'_>, messages: &Bound<'_, PyList>) -> PyResult<Py<PyBytes>> {
    let mut hasher = Sha256::new();
    for (index, item) in messages.iter().enumerate() {
        let message = item
            .downcast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err(format!("transcript message {index} must be bytes")))?;
        hasher.update(message.as_bytes());
    }
    let digest = hasher.finalize();
    Ok(PyBytes::new_bound(py, digest.as_slice()).into())
}

#[pyfunction]
pub fn hmac_sha256(py: Python<'_>, key: &[u8], data: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("invalid key: {e}")))?;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    Ok(PyBytes::new_bound(py, &out).into())
}

#[pyfunction]
pub fn sha256_digest(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    let digest = Sha256::digest(data);
    PyBytes::new_bound(py, &digest).into()
}

#[pyfunction]
pub fn sha256_hex(data: &str) -> String {
    let digest = Sha256::digest(data.as_bytes());
    hex::encode(digest)
}

#[pyfunction]
pub fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

#[pyfunction]
pub fn xor_iv_with_seq(py: Python<'_>, iv: &[u8], seq: u64) -> PyResult<Py<PyBytes>> {
    if iv.len() != 12 {
        return Err(PyValueError::new_err("Invalid iv size: expected 12 bytes"));
    }

    let mut padded_seq = [0u8; 12];
    padded_seq[4..].copy_from_slice(&seq.to_be_bytes());
    let derived: Vec<u8> = iv
        .iter()
        .zip(padded_seq.iter())
        .map(|(left, right)| left ^ right)
        .collect();
    Ok(PyBytes::new_bound(py, &derived).into())
}

#[pyfunction]
pub fn aead_seal(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("Invalid key size: expected 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err("Invalid nonce size: expected 12 bytes"));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("invalid key: {e}")))?;
    let nonce_ref = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce_ref, Payload { msg: plaintext, aad })
        .map_err(|e| PyValueError::new_err(format!("encryption failed: {e}")))?;
    Ok(PyBytes::new_bound(py, &ciphertext).into())
}

#[pyfunction]
pub fn aead_open(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("Invalid key size: expected 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err("Invalid nonce size: expected 12 bytes"));
    }
    if ciphertext.len() < 16 {
        return Err(PyValueError::new_err(
            "ciphertext must be at least 16 bytes to include an authentication tag",
        ));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| PyValueError::new_err(format!("invalid key: {e}")))?;
    let nonce_ref = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce_ref, Payload { msg: ciphertext, aad })
        .map_err(|_| PyValueError::new_err("authentication tag verification failed"))?;
    Ok(PyBytes::new_bound(py, &plaintext).into())
}
