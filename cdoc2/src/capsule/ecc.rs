use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret, diffie_hellman};
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize, Generate, PublicKey, SecretKey,
};

use crate::capsule::{Capsule, expand_kek, record_with_kek};
use crate::crypto::{FMK_LEN, HashAlgorithm};
use crate::header::RecipientRecord;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcPublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
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
    pub(crate) fn generate(
        recipient: &EcPublicKey,
    ) -> Result<(Self, [u8; FMK_LEN]), getrandom::Error> {
        match recipient {
            EcPublicKey::P256(key) => Self::generate_curve(EllipticCurve::Secp256r1, key),
            EcPublicKey::P384(key) => Self::generate_curve(EllipticCurve::Secp384r1, key),
            EcPublicKey::P521(key) => Self::generate_curve(EllipticCurve::Secp521r1, key),
        }
    }

    fn generate_curve<C>(
        curve: EllipticCurve,
        recipient: &PublicKey<C>,
    ) -> Result<(Self, [u8; FMK_LEN]), getrandom::Error>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    {
        let ephemeral_secret = EphemeralSecret::<C>::try_generate()?;
        let capsule = Self {
            curve,
            recipient_public_key: recipient.to_sec1_point(false).as_bytes().to_vec(),
            sender_public_key: ephemeral_secret
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        };
        let shared_secret = ephemeral_secret.diffie_hellman(recipient);
        let kek = capsule.kek_from_shared_secret(&shared_secret);
        Ok((capsule, kek))
    }

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

pub(crate) fn recipient_record(
    public_key: &EcPublicKey,
    key_label: &str,
    fmk: &[u8; FMK_LEN],
) -> Result<RecipientRecord, getrandom::Error> {
    let (capsule, kek) = EccPublicKeyCapsule::generate(public_key)?;
    Ok(record_with_kek(Capsule::Ecc(capsule), key_label, &kek, fmk))
}
