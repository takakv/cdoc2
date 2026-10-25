use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret, diffie_hellman};
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{Curve, CurveArithmetic, FieldBytes, Generate, PublicKey, SecretKey};

use crate::capsule::{Capsule, encrypt_fmk, expand_kek};
use crate::crypto::{FMK_LEN, HashAlgorithm};
use crate::header::RecipientRecord;

const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

trait NistCurve:
    Curve<FieldBytesSize: ModulusSize>
    + CurveArithmetic<AffinePoint: FromSec1Point<Self> + ToSec1Point<Self>>
{
    const CURVE: EllipticCurve;
}

impl NistCurve for p256::NistP256 {
    const CURVE: EllipticCurve = EllipticCurve::Secp256r1;
}

impl NistCurve for p384::NistP384 {
    const CURVE: EllipticCurve = EllipticCurve::Secp384r1;
}

impl NistCurve for p521::NistP521 {
    const CURVE: EllipticCurve = EllipticCurve::Secp521r1;
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EccKekError {
    #[error("the key is not on the recipient's curve")]
    CurveMismatch,
    #[error("the sender's public key is invalid")]
    InvalidSenderKey,
    #[error("the shared secret has the wrong length for the curve: {0} bytes")]
    InvalidSharedSecretLength(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EccPublicKeyCapsule {
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub(crate) sender_public_key: Vec<u8>,
}

impl EccPublicKeyCapsule {
    pub(crate) fn generate(
        recipient: &EcPublicKey,
    ) -> Result<(Self, [u8; FMK_LEN]), getrandom::Error> {
        match recipient {
            EcPublicKey::P256(key) => Self::generate_curve(key),
            EcPublicKey::P384(key) => Self::generate_curve(key),
            EcPublicKey::P521(key) => Self::generate_curve(key),
        }
    }

    fn generate_curve<C: NistCurve>(
        recipient: &PublicKey<C>,
    ) -> Result<(Self, [u8; FMK_LEN]), getrandom::Error> {
        let ephemeral_secret = EphemeralSecret::<C>::try_generate()?;
        let capsule = Self {
            curve: C::CURVE,
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

    pub(crate) fn derive_kek(
        &self,
        secret_key: &EcSecretKey,
    ) -> Result<[u8; FMK_LEN], EccKekError> {
        match secret_key {
            EcSecretKey::P256(key) => self.derive_curve_kek(key),
            EcSecretKey::P384(key) => self.derive_curve_kek(key),
            EcSecretKey::P521(key) => self.derive_curve_kek(key),
        }
    }

    fn derive_curve_kek<C: NistCurve>(
        &self,
        secret_key: &SecretKey<C>,
    ) -> Result<[u8; FMK_LEN], EccKekError> {
        if self.curve != C::CURVE {
            return Err(EccKekError::CurveMismatch);
        }
        let pk = self.sender_point::<C>()?;
        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), pk.as_affine());
        Ok(self.kek_from_shared_secret(&shared_secret))
    }

    pub fn sender_public_key(&self) -> Result<&[u8], EccKekError> {
        match self.curve {
            EllipticCurve::Secp256r1 => self.sender_point::<p256::NistP256>().map(drop),
            EllipticCurve::Secp384r1 => self.sender_point::<p384::NistP384>().map(drop),
            EllipticCurve::Secp521r1 => self.sender_point::<p521::NistP521>().map(drop),
        }?;
        Ok(&self.sender_public_key)
    }

    fn sender_point<C: NistCurve>(&self) -> Result<PublicKey<C>, EccKekError> {
        if self.sender_public_key.first() != Some(&UNCOMPRESSED_POINT_TAG) {
            return Err(EccKekError::InvalidSenderKey);
        }
        PublicKey::<C>::from_sec1_bytes(&self.sender_public_key)
            .map_err(|_| EccKekError::InvalidSenderKey)
    }

    pub(crate) fn derive_kek_from_shared_secret(
        &self,
        shared_secret: &[u8],
    ) -> Result<[u8; FMK_LEN], EccKekError> {
        match self.curve {
            EllipticCurve::Secp256r1 => {
                self.kek_from_raw_shared_secret::<p256::NistP256>(shared_secret)
            }
            EllipticCurve::Secp384r1 => {
                self.kek_from_raw_shared_secret::<p384::NistP384>(shared_secret)
            }
            EllipticCurve::Secp521r1 => {
                self.kek_from_raw_shared_secret::<p521::NistP521>(shared_secret)
            }
        }
    }

    fn kek_from_raw_shared_secret<C: Curve>(
        &self,
        shared_secret: &[u8],
    ) -> Result<[u8; FMK_LEN], EccKekError> {
        let bytes = FieldBytes::<C>::try_from(shared_secret)
            .map_err(|_| EccKekError::InvalidSharedSecretLength(shared_secret.len()))?;
        Ok(self.kek_from_shared_secret(&SharedSecret::<C>::from(bytes)))
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
    Ok(RecipientRecord::new(
        Capsule::Ecc(capsule),
        key_label,
        encrypt_fmk(fmk, &kek),
    ))
}
