use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret, StaticSecret as X25519Secret};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use hkdf::Hkdf;
use sha2::Sha256;

pub mod identity;

/// Algorithms supported for the initial key exchange.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyExchangeAlgorithm {
    X25519,
    EcdhP256,
    None,
}

/// Derived session key material.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub shared_secret: Vec<u8>,
    pub control_key: [u8; 32],
    pub stream_key: [u8; 32],
}

/// Behavior required to complete the handshake key agreement.
pub trait KeyExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm;
    fn public_key(&self) -> Vec<u8>;
    fn derive_keys(&self, peer_public_key: &[u8], salt: &[u8]) -> Result<SessionKeys, CryptoError>;
}

/// Lightweight placeholder for X25519; replace with a real implementation later.
pub struct X25519KeyExchange {
    public_key: X25519PublicKey,
    private_key: X25519Secret,
}

impl X25519KeyExchange {
    pub fn new() -> Self {
        let private_key = X25519Secret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            public_key,
            private_key,
        }
    }
}

impl Default for X25519KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExchange for X25519KeyExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm {
        KeyExchangeAlgorithm::X25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    fn derive_keys(&self, peer_public_key: &[u8], salt: &[u8]) -> Result<SessionKeys, CryptoError> {
        let peer_bytes: [u8; 32] = peer_public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidPeerKey)?;
        let peer_pk = X25519PublicKey::from(peer_bytes);
        let shared_secret: SharedSecret = self.private_key.diffie_hellman(&peer_pk);
        let shared_secret_bytes = shared_secret.as_bytes().to_vec();

        let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
        let mut control_key = [0u8; 32];
        let mut stream_key = [0u8; 32];
        hkdf.expand(b"alpine-control", &mut control_key)
            .map_err(|e| CryptoError::Hkdf(format!("{:?}", e)))?;
        hkdf.expand(b"alpine-stream", &mut stream_key)
            .map_err(|e| CryptoError::Hkdf(format!("{:?}", e)))?;

        Ok(SessionKeys {
            shared_secret: shared_secret_bytes,
            control_key,
            stream_key,
        })
    }
}

/// Interface that would wrap an external TLS channel when available.
pub trait TlsWrapper {
    fn wrap_stream(&self, plaintext: &[u8]) -> Vec<u8>;
    fn unwrap_stream(&self, ciphertext: &[u8]) -> Vec<u8>;
}

/// Cryptographic helper errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid peer public key")]
    InvalidPeerKey,
    #[error("hkdf expand error: {0}")]
    Hkdf(String),
    #[error("aead error: {0}")]
    Aead(String),
}

/// Compute an authentication tag for a control payload using the derived control key.
pub fn compute_mac(
    keys: &SessionKeys,
    seq: u64,
    payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(&keys.control_key);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&seq.to_be_bytes());
    let mut buffer = payload.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce.into(), aad, &mut buffer)
        .map_err(|e| CryptoError::Aead(e.to_string()))?;
    Ok(tag.to_vec())
}

/// Validate an authentication tag for a control payload.
pub fn verify_mac(keys: &SessionKeys, seq: u64, payload: &[u8], aad: &[u8], mac: &[u8]) -> bool {
    const CHACHA_TAG_SIZE: usize = 16;
    if mac.len() != CHACHA_TAG_SIZE {
        return false;
    }
    match compute_mac(keys, seq, payload, aad) {
        Ok(expected) => expected == mac,
        Err(_) => false,
    }
}
