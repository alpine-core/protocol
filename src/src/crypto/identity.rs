use std::fs::File;
use std::io::BufReader;

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::{Signer, Verifier};
use thiserror::Error;

/// Ed25519 credentials loaded from PEM files.
#[derive(Clone)]
pub struct NodeCredentials {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to parse PEM: {0}")]
    Pem(String),
    #[error("missing key material in PEM")]
    MissingKey,
}

impl NodeCredentials {
    pub fn load_signing_pem(path: &str) -> Result<SigningKey, IdentityError> {
        let file = File::open(path).map_err(|e| IdentityError::Pem(e.to_string()))?;
        let mut reader = BufReader::new(file);
        let key_der = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .next()
            .ok_or(IdentityError::MissingKey)?
            .map_err(|e| IdentityError::Pem(format!("pkcs8 parse: {}", e)))?;
        SigningKey::from_pkcs8_der(key_der.secret_pkcs8_der())
            .map_err(|e| IdentityError::Pem(e.to_string()))
    }

    pub fn load_verifying_pem(path: &str) -> Result<VerifyingKey, IdentityError> {
        let file = File::open(path).map_err(|e| IdentityError::Pem(e.to_string()))?;
        let mut reader = BufReader::new(file);
        let cert = rustls_pemfile::certs(&mut reader)
            .next()
            .ok_or(IdentityError::MissingKey)?
            .map_err(|e| IdentityError::Pem(format!("cert parse: {}", e)))?;
        VerifyingKey::from_public_key_der(cert.as_ref())
            .map_err(|e| IdentityError::Pem(e.to_string()))
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing.sign(data)
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> bool {
        self.verifying.verify(data, sig).is_ok()
    }
}
