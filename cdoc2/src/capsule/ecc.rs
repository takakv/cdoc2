use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret, diffie_hellman};
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{Curve, CurveArithmetic, FieldBytes, Generate, PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::capsule::{Capsule, encrypt_fmk, expand_kek};
use crate::crypto::{FMK_LEN, HashAlgorithm, Kek};
use crate::header::RecipientRecord;
use crate::keys::{EcPublicKey, EcSecretKey, EcdhKey, EllipticCurve};

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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EccKekError {
    #[error("the key is not on the recipient's curve")]
    CurveMismatch,
    #[error("the sender's public key is invalid")]
    InvalidSenderKey,
    #[error("the shared secret has the wrong length for the curve: {0} bytes")]
    InvalidSharedSecretLength(usize),
    #[error("the key could not compute ECDH: {0}")]
    Ecdh(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EccPublicKeyCapsule {
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub(crate) sender_public_key: Vec<u8>,
}

impl EccPublicKeyCapsule {
    pub(crate) fn generate(recipient: &EcPublicKey) -> Result<(Self, Kek), getrandom::Error> {
        match recipient {
            EcPublicKey::P256(key) => Self::generate_curve(key),
            EcPublicKey::P384(key) => Self::generate_curve(key),
            EcPublicKey::P521(key) => Self::generate_curve(key),
        }
    }

    fn generate_curve<C: NistCurve>(
        recipient: &PublicKey<C>,
    ) -> Result<(Self, Kek), getrandom::Error> {
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

    pub(crate) fn derive_kek(&self, secret_key: &EcSecretKey) -> Result<Kek, EccKekError> {
        match secret_key {
            EcSecretKey::P256(key) => self.derive_curve_kek(key),
            EcSecretKey::P384(key) => self.derive_curve_kek(key),
            EcSecretKey::P521(key) => self.derive_curve_kek(key),
        }
    }

    fn derive_curve_kek<C: NistCurve>(
        &self,
        secret_key: &SecretKey<C>,
    ) -> Result<Kek, EccKekError> {
        if self.curve != C::CURVE {
            return Err(EccKekError::CurveMismatch);
        }
        let pk = self.sender_point::<C>()?;
        let shared_secret = diffie_hellman(secret_key.to_nonzero_scalar(), pk.as_affine());
        Ok(self.kek_from_shared_secret(&shared_secret))
    }

    pub(crate) fn derive_kek_with(&self, key: &dyn EcdhKey) -> Result<Kek, EccKekError> {
        if key.curve() != self.curve {
            return Err(EccKekError::CurveMismatch);
        }
        let shared_secret =
            Zeroizing::new(key.ecdh(&self.sender_key()?).map_err(EccKekError::Ecdh)?);
        self.derive_kek_from_shared_secret(&shared_secret)
    }

    fn sender_key(&self) -> Result<EcPublicKey, EccKekError> {
        Ok(match self.curve {
            EllipticCurve::Secp256r1 => EcPublicKey::P256(self.sender_point()?),
            EllipticCurve::Secp384r1 => EcPublicKey::P384(self.sender_point()?),
            EllipticCurve::Secp521r1 => EcPublicKey::P521(self.sender_point()?),
        })
    }

    fn sender_point<C: NistCurve>(&self) -> Result<PublicKey<C>, EccKekError> {
        if self.sender_public_key.first() != Some(&UNCOMPRESSED_POINT_TAG) {
            return Err(EccKekError::InvalidSenderKey);
        }
        PublicKey::<C>::from_sec1_bytes(&self.sender_public_key)
            .map_err(|_| EccKekError::InvalidSenderKey)
    }

    fn derive_kek_from_shared_secret(&self, shared_secret: &[u8]) -> Result<Kek, EccKekError> {
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
    ) -> Result<Kek, EccKekError> {
        let bytes = FieldBytes::<C>::try_from(shared_secret)
            .map_err(|_| EccKekError::InvalidSharedSecretLength(shared_secret.len()))?;
        Ok(self.kek_from_shared_secret(&SharedSecret::<C>::from(bytes)))
    }

    fn kek_from_shared_secret<C: Curve>(&self, shared_secret: &SharedSecret<C>) -> Kek {
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
