use elliptic_curve::ecdh::{SharedSecret, diffie_hellman};
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey};

use crate::capsule::expand_kek;
use crate::crypto::{FMK_LEN, HashAlgorithm};

const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

#[derive(Debug, Clone)]
pub enum EcSecretKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EccKekError {
    #[error("the key is not on the recipient's curve")]
    CurveMismatch,
    #[error("the sender's public key is invalid")]
    InvalidSenderKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublicKeyCapsule {
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub sender_public_key: Vec<u8>,
}

impl EccPublicKeyCapsule {
    pub fn derive_kek(&self, secret_key: &EcSecretKey) -> Result<[u8; FMK_LEN], EccKekError> {
        match (self.curve, secret_key) {
            (EllipticCurve::Secp256r1, EcSecretKey::P256(key)) => self.derive_curve_kek(key),
            (EllipticCurve::Secp384r1, EcSecretKey::P384(key)) => self.derive_curve_kek(key),
            (EllipticCurve::Secp521r1, EcSecretKey::P521(key)) => self.derive_curve_kek(key),
            _ => Err(EccKekError::CurveMismatch),
        }
    }

    fn derive_curve_kek<C>(&self, secret_key: &SecretKey<C>) -> Result<[u8; FMK_LEN], EccKekError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    {
        if self.sender_public_key.first() != Some(&UNCOMPRESSED_POINT_TAG) {
            return Err(EccKekError::InvalidSenderKey);
        }
        let pk = PublicKey::<C>::from_sec1_bytes(&self.sender_public_key)
            .map_err(|_| EccKekError::InvalidSenderKey)?;
        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), pk.as_affine());
        Ok(self.kek_from_shared_secret(&shared_secret))
    }

    fn kek_from_shared_secret<C: Curve>(&self, shared_secret: &SharedSecret<C>) -> [u8; FMK_LEN] {
        let hk = shared_secret.extract::<HashAlgorithm>(Some(b"CDOC20kekpremaster"));
        expand_kek(&hk, &[&self.recipient_public_key, &self.sender_public_key])
    }
}
