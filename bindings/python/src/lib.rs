// PyO3 macros generate code that triggers warnings in Rust 2024 edition:
// - `unsafe_op_in_unsafe_fn`: PyO3 macro-generated code uses unsafe operations
// - `clippy::useless_conversion`: False positives from PyO3's error handling macros
// See: https://github.com/PyO3/pyo3/issues/3585
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::useless_conversion)]

use ed25519_dalek::VerifyingKey;
use pyo3::Bound;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule};
use rand::rng;
use serde_json::{self, Value};
use syftbox_crypto_protocol as protocol;

fn to_py_err<E: std::fmt::Display>(err: E) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn any_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if let Ok(text) = value.extract::<String>() {
        return serde_json::from_str(&text).map_err(to_py_err);
    }

    let py = value.py();
    let json = PyModule::import(py, "json")?;
    let dumped: String = json.call_method1("dumps", (value,))?.extract()?;
    serde_json::from_str(&dumped).map_err(to_py_err)
}

fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<PyObject> {
    let json = PyModule::import(py, "json")?;
    let dumped = serde_json::to_string(value).map_err(to_py_err)?;
    Ok(json.call_method1("loads", (dumped,))?.into())
}

#[pyclass(name = "SyftRecoveryKey")]
pub struct PySyftRecoveryKey {
    inner: protocol::SyftRecoveryKey,
}

#[pymethods]
impl PySyftRecoveryKey {
    /// Generate a new random recovery key.
    #[staticmethod]
    pub fn generate() -> Self {
        Self {
            inner: protocol::SyftRecoveryKey::generate(),
        }
    }

    /// Parse a recovery key from a hex string (dashes optional).
    #[staticmethod]
    pub fn from_hex_string(value: &str) -> PyResult<Self> {
        let inner = protocol::SyftRecoveryKey::from_hex_string(value).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse a recovery key from a BIP39 mnemonic phrase.
    #[staticmethod]
    pub fn from_mnemonic(value: &str) -> PyResult<Self> {
        let inner = protocol::SyftRecoveryKey::from_mnemonic(value).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Return the recovery key formatted as dashed hex.
    pub fn to_hex_string(&self) -> String {
        self.inner.to_hex_string()
    }

    /// Return the recovery key as a 24-word mnemonic.
    pub fn to_mnemonic(&self) -> String {
        self.inner.to_mnemonic()
    }

    /// Derive private keys from the recovery key.
    pub fn derive_keys(&self) -> PyResult<PySyftPrivateKeys> {
        let keys = self.inner.derive_keys().map_err(to_py_err)?;
        Ok(PySyftPrivateKeys { inner: keys })
    }
}

#[pyclass(name = "SyftPrivateKeys")]
pub struct PySyftPrivateKeys {
    inner: protocol::keys::SyftPrivateKeys,
}

#[pymethods]
impl PySyftPrivateKeys {
    /// Reconstruct private keys from a JWKS structure.
    #[staticmethod]
    pub fn from_jwks(value: Bound<'_, PyAny>) -> PyResult<Self> {
        let json = any_to_json(&value)?;
        let inner = protocol::serialization::deserialize_private_keys(&json).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Serialize private keys to JWKS JSON.
    pub fn to_jwks(&self, py: Python<'_>) -> PyResult<PyObject> {
        let json =
            protocol::serialization::serialize_private_keys(&self.inner).map_err(to_py_err)?;
        json_to_py(py, &json)
    }

    /// Create a public bundle from the private keys.
    pub fn to_public_bundle(&self) -> PyResult<PySyftPublicKeyBundle> {
        let mut rng = rng();
        let bundle = self.inner.to_public_bundle(&mut rng).map_err(to_py_err)?;
        Ok(PySyftPublicKeyBundle { inner: bundle })
    }
}

#[pyclass(name = "SyftPublicKeyBundle")]
#[derive(Clone)]
pub struct PySyftPublicKeyBundle {
    inner: protocol::keys::SyftPublicKeyBundle,
}

#[pymethods]
impl PySyftPublicKeyBundle {
    /// Deserialize a public bundle from a DID document.
    #[staticmethod]
    pub fn from_did_document(value: Bound<'_, PyAny>) -> PyResult<Self> {
        let json = any_to_json(&value)?;
        let inner =
            protocol::serialization::deserialize_from_did_document(&json).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Serialize the bundle to a DID document with the provided DID id.
    pub fn to_did_document(&self, py: Python<'_>, did: &str) -> PyResult<PyObject> {
        let json = protocol::serialization::serialize_to_did_document(&self.inner, did)
            .map_err(to_py_err)?;
        json_to_py(py, &json)
    }

    /// Fingerprint of the identity key in the bundle.
    pub fn identity_fingerprint(&self) -> String {
        self.inner.identity_fingerprint()
    }

    /// Serialized identity public key bytes (for signature verification).
    #[getter]
    pub fn identity_key_bytes<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, self.inner.identity_signing_public_key.as_bytes()).into()
    }

    /// Verify bundle signatures.
    pub fn verify_signatures(&self) -> bool {
        self.inner.verify_signatures()
    }

    /// Total serialized size in bytes.
    pub fn total_size(&self) -> usize {
        self.inner.total_size()
    }
}

#[pyclass(name = "EncryptionRecipient")]
#[derive(Clone)]
pub struct PyEncryptionRecipient {
    identity: String,
    bundle: protocol::keys::SyftPublicKeyBundle,
}

#[pymethods]
impl PyEncryptionRecipient {
    #[new]
    pub fn new(identity: String, bundle: PyRef<PySyftPublicKeyBundle>) -> Self {
        Self {
            identity,
            bundle: bundle.inner.clone(),
        }
    }

    #[getter]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    #[getter]
    pub fn bundle(&self) -> PySyftPublicKeyBundle {
        PySyftPublicKeyBundle {
            inner: self.bundle.clone(),
        }
    }
}

#[pyclass(name = "IdentityMaterial")]
pub struct PyIdentityMaterial {
    inner: protocol::identity::IdentityMaterial,
}

#[pymethods]
impl PyIdentityMaterial {
    #[getter]
    pub fn fingerprint(&self) -> &str {
        &self.inner.fingerprint
    }

    #[getter]
    pub fn did(&self) -> &str {
        &self.inner.did
    }

    #[getter]
    pub fn recovery_key_hex(&self) -> &str {
        self.inner.recovery_key_hex.as_str()
    }

    #[getter]
    pub fn recovery_key_mnemonic(&self) -> &str {
        self.inner.recovery_key_mnemonic.as_str()
    }

    #[getter]
    pub fn key_file<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.key_file).into()
    }

    #[getter]
    pub fn public_bundle<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        json_to_py(py, &self.inner.public_bundle)
    }
}

#[pyclass(name = "ParsedEnvelope")]
#[derive(Clone)]
pub struct PyParsedEnvelope {
    inner: protocol::envelope::ParsedEnvelope,
}

#[pymethods]
impl PyParsedEnvelope {
    #[getter]
    pub fn prelude<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let prelude_json = serde_json::to_value(&self.inner.prelude).map_err(to_py_err)?;
        json_to_py(py, &prelude_json)
    }

    #[getter]
    pub fn prelude_bytes<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.prelude_bytes).into()
    }

    #[getter]
    pub fn signature<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.signature).into()
    }

    #[getter]
    pub fn ciphertext<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.ciphertext).into()
    }
}

#[pyfunction]
pub fn compute_key_fingerprint(key_bytes: &[u8]) -> String {
    protocol::compute_key_fingerprint(key_bytes)
}

#[pyfunction]
pub fn compute_identity_fingerprint(identity_key_bytes: &[u8]) -> PyResult<String> {
    let identity_key_bytes: [u8; 32] = identity_key_bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("invalid identity key bytes"))?;
    let identity_key = VerifyingKey::from_bytes(&identity_key_bytes)
        .map_err(|_| PyValueError::new_err("invalid identity key bytes"))?;
    Ok(protocol::compute_identity_fingerprint(&identity_key))
}

#[pyfunction]
pub fn generate_identity_material(identity: &str) -> PyResult<PyIdentityMaterial> {
    let inner = protocol::generate_identity_material(identity).map_err(to_py_err)?;
    Ok(PyIdentityMaterial { inner })
}

#[pyfunction]
pub fn parse_envelope(bytes: &[u8]) -> PyResult<PyParsedEnvelope> {
    let inner = protocol::envelope::parse_envelope(bytes).map_err(to_py_err)?;
    Ok(PyParsedEnvelope { inner })
}

#[pyfunction]
pub fn verify_envelope_signature(
    envelope: &PyParsedEnvelope,
    sender_identity_key: &[u8],
) -> PyResult<()> {
    let identity_key_bytes: [u8; 32] = sender_identity_key
        .try_into()
        .map_err(|_| PyValueError::new_err("invalid sender identity key"))?;
    let identity_key = VerifyingKey::from_bytes(&identity_key_bytes)
        .map_err(|_| PyValueError::new_err("invalid sender identity key"))?;
    protocol::envelope::verify_signature(&envelope.inner, &identity_key).map_err(to_py_err)
}

#[pyfunction(signature = (sender_identity, sender_keys, recipients, plaintext, filename_hint=None))]
pub fn encrypt_message(
    py: Python<'_>,
    sender_identity: &str,
    sender_keys: &PySyftPrivateKeys,
    recipients: Vec<Py<PyEncryptionRecipient>>,
    plaintext: &[u8],
    filename_hint: Option<String>,
) -> PyResult<Py<PyBytes>> {
    let mut bundles = Vec::with_capacity(recipients.len());
    let mut identities = Vec::with_capacity(recipients.len());

    for recipient in &recipients {
        let recipient = recipient.borrow(py);
        identities.push(recipient.identity.clone());
        bundles.push(recipient.bundle.clone());
    }

    let mut enc_recipients = Vec::with_capacity(recipients.len());
    for (identity, bundle) in identities.iter().zip(bundles.iter()) {
        enc_recipients.push(protocol::encryption::EncryptionRecipient { identity, bundle });
    }

    let mut rng = rng();
    let envelope = protocol::encrypt_message(
        sender_identity,
        &sender_keys.inner,
        &enc_recipients,
        plaintext,
        filename_hint.as_deref(),
        &mut rng,
    )
    .map_err(to_py_err)?;

    Ok(PyBytes::new(py, &envelope).into())
}

#[pyfunction]
pub fn decrypt_message(
    py: Python<'_>,
    recipient_identity: &str,
    recipient_keys: &PySyftPrivateKeys,
    sender_bundle: &PySyftPublicKeyBundle,
    envelope: &PyParsedEnvelope,
) -> PyResult<Py<PyBytes>> {
    let plaintext = protocol::decrypt_message(
        recipient_identity,
        &recipient_keys.inner,
        &sender_bundle.inner,
        &envelope.inner,
    )
    .map_err(to_py_err)?;

    Ok(PyBytes::new(py, &plaintext).into())
}

/// Python module definition.
#[pymodule(name = "_native")]
fn _native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySyftRecoveryKey>()?;
    m.add_class::<PySyftPrivateKeys>()?;
    m.add_class::<PySyftPublicKeyBundle>()?;
    m.add_class::<PyEncryptionRecipient>()?;
    m.add_class::<PyIdentityMaterial>()?;
    m.add_class::<PyParsedEnvelope>()?;

    m.add_function(wrap_pyfunction!(compute_key_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(compute_identity_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(generate_identity_material, m)?)?;
    m.add_function(wrap_pyfunction!(parse_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(verify_envelope_signature, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_message, m)?)?;

    Ok(())
}
