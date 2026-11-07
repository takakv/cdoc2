//! Elliptic curve keys.

use std::error::Error;
use std::sync::Arc;

use elliptic_curve::sec1::ToSec1Point;

pub use {p256, p384, p521};

use crate::crypto::with_wiped_stack;

/// An elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    /// NIST P-256.
    Secp256r1,
    /// NIST P-384.
    Secp384r1,
    /// NIST P-521.
    Secp521r1,
}

/// A private key that computes ECDH itself, such as the key on an ID card.
///
/// Decrypt with it by passing it as
/// [`DecryptionKey::Ecdh`](crate::decrypt::DecryptionKey::Ecdh). Before calling
/// [`ecdh`](EcdhKey::ecdh), decryption checks that the recipient is on the key's curve and that
/// the sender's public key is a valid point.
pub trait EcdhKey {
    /// Returns the key's curve.
    fn curve(&self) -> EllipticCurve;

    /// Computes the ECDH shared secret with the sender's public key.
    ///
    /// Returns the x-coordinate of the shared point as big-endian bytes, zero-padded to 32 bytes
    /// for P-256, 48 for P-384 and 66 for P-521.
    ///
    /// # Errors
    ///
    /// Return an error if the key can't compute the secret. Decryption then fails with
    /// [`EccKekError::Ecdh`](crate::capsule::ecc::EccKekError::Ecdh).
    fn ecdh(
        &self,
        sender_public_key: &EcPublicKey,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
}

/// An error returned by an [`EcdhKey`].
#[derive(Debug, Clone, thiserror::Error)]
#[error(transparent)]
pub struct EcdhError(Arc<dyn Error + Send + Sync>);

impl EcdhError {
    /// Returns the error that the key returned.
    pub fn get_ref(&self) -> &(dyn Error + Send + Sync + 'static) {
        &*self.0
    }
}

impl From<Box<dyn Error + Send + Sync>> for EcdhError {
    fn from(error: Box<dyn Error + Send + Sync>) -> Self {
        EcdhError(error.into())
    }
}

/// Two `EcdhError`s are equal if their messages are.
impl PartialEq for EcdhError {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_string() == other.0.to_string()
    }
}

impl Eq for EcdhError {}

/// An elliptic curve private key held in memory.
#[derive(Debug, Clone)]
pub enum EcSecretKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

/// An elliptic curve public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcPublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
}

impl EcSecretKey {
    /// Returns the matching public key.
    pub fn public_key(&self) -> EcPublicKey {
        with_wiped_stack(|| match self {
            EcSecretKey::P256(key) => EcPublicKey::P256(key.public_key()),
            EcSecretKey::P384(key) => EcPublicKey::P384(key.public_key()),
            EcSecretKey::P521(key) => EcPublicKey::P521(key.public_key()),
        })
    }
}

impl EcPublicKey {
    /// Returns the key's curve.
    pub fn curve(&self) -> EllipticCurve {
        match self {
            EcPublicKey::P256(_) => EllipticCurve::Secp256r1,
            EcPublicKey::P384(_) => EllipticCurve::Secp384r1,
            EcPublicKey::P521(_) => EllipticCurve::Secp521r1,
        }
    }

    /// Encodes the key as an uncompressed SEC1 point.
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        match self {
            EcPublicKey::P256(key) => key.to_sec1_point(false).as_bytes().to_vec(),
            EcPublicKey::P384(key) => key.to_sec1_point(false).as_bytes().to_vec(),
            EcPublicKey::P521(key) => key.to_sec1_point(false).as_bytes().to_vec(),
        }
    }
}
