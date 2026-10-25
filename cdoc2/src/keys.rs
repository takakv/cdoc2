use elliptic_curve::sec1::ToSec1Point;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

/// A private key that computes ECDH itself, e.g. an ID card private key.
pub trait EcdhKey {
    fn curve(&self) -> EllipticCurve;
    fn ecdh(&self, sender_public_key: &EcPublicKey) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Clone)]
pub enum EcSecretKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcPublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
}

impl EcSecretKey {
    pub fn public_key(&self) -> EcPublicKey {
        match self {
            EcSecretKey::P256(key) => EcPublicKey::P256(key.public_key()),
            EcSecretKey::P384(key) => EcPublicKey::P384(key.public_key()),
            EcSecretKey::P521(key) => EcPublicKey::P521(key.public_key()),
        }
    }
}

impl EcPublicKey {
    pub fn curve(&self) -> EllipticCurve {
        match self {
            EcPublicKey::P256(_) => EllipticCurve::Secp256r1,
            EcPublicKey::P384(_) => EllipticCurve::Secp384r1,
            EcPublicKey::P521(_) => EllipticCurve::Secp521r1,
        }
    }

    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        match self {
            EcPublicKey::P256(key) => key.to_sec1_point(false).as_bytes().to_vec(),
            EcPublicKey::P384(key) => key.to_sec1_point(false).as_bytes().to_vec(),
            EcPublicKey::P521(key) => key.to_sec1_point(false).as_bytes().to_vec(),
        }
    }
}
