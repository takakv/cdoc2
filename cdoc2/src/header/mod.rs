#[allow(dead_code, unused_imports, clippy::all)]
#[rustfmt::skip]
mod generated;

use flatbuffers::{FlatBufferBuilder, UnionWIPOffset, WIPOffset};

use crate::capsule::Capsule;
use crate::capsule::password::Pbkdf2Capsule;
use crate::capsule::symmetric::SymmetricKeyCapsule;
use generated::ee::cyber::cdoc_2::fbs::header as fb;
use generated::ee::cyber::cdoc_2::fbs::recipients as fb_rec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub recipients: Vec<RecipientRecord>,
    pub payload_encryption_method: PayloadEncryptionMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecord {
    pub capsule: Capsule,
    pub key_label: String,
    pub encrypted_fmk: Vec<u8>,
    pub fmk_encryption_method: FmkEncryptionMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FmkEncryptionMethod {
    Xor,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncryptionMethod {
    ChaCha20Poly1305,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("malformed header: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SerializeError {
    #[error("cannot serialize an unsupported capsule")]
    UnsupportedCapsule,
    #[error("cannot serialize an unknown FMK encryption method")]
    UnknownFmkEncryptionMethod,
    #[error("cannot serialize an unknown payload encryption method")]
    UnknownPayloadEncryptionMethod,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Header, HeaderError> {
        let header =
            fb::root_as_header(bytes).map_err(|e| HeaderError::Malformed(e.to_string()))?;

        let payload_encryption_method = match header.payload_encryption_method() {
            fb::PayloadEncryptionMethod::CHACHA20POLY1305 => {
                PayloadEncryptionMethod::ChaCha20Poly1305
            }
            _ => PayloadEncryptionMethod::Unknown,
        };

        let recipients = header
            .recipients()
            .map(|records| records.iter().map(RecipientRecord::from_fb).collect())
            .unwrap_or_default();

        Ok(Header {
            recipients,
            payload_encryption_method,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializeError> {
        let payload_encryption_method = match self.payload_encryption_method {
            PayloadEncryptionMethod::ChaCha20Poly1305 => {
                fb::PayloadEncryptionMethod::CHACHA20POLY1305
            }
            PayloadEncryptionMethod::Unknown => {
                return Err(SerializeError::UnknownPayloadEncryptionMethod);
            }
        };

        let mut fbb = FlatBufferBuilder::new();
        let records = self
            .recipients
            .iter()
            .map(|record| record.to_fb(&mut fbb))
            .collect::<Result<Vec<_>, _>>()?;
        let recipients = fbb.create_vector(&records);

        let header = fb::Header::create(
            &mut fbb,
            &fb::HeaderArgs {
                recipients: Some(recipients),
                payload_encryption_method,
            },
        );
        fbb.finish(header, None);
        Ok(fbb.finished_data().to_vec())
    }
}

impl RecipientRecord {
    fn from_fb(record: fb::RecipientRecord<'_>) -> RecipientRecord {
        let capsule = if let Some(c) = record.capsule_as_recipients_symmetric_key_capsule() {
            symmetric_capsule_from_fb(c)
        } else if let Some(c) = record.capsule_as_recipients_pbkdf2_capsule() {
            password_capsule_from_fb(c)
        } else {
            Capsule::Unsupported
        };

        let fmk_encryption_method = match record.fmk_encryption_method() {
            fb::FMKEncryptionMethod::XOR => FmkEncryptionMethod::Xor,
            _ => FmkEncryptionMethod::Unknown,
        };

        RecipientRecord {
            capsule,
            key_label: record.key_label().to_owned(),
            encrypted_fmk: record.encrypted_fmk().bytes().to_vec(),
            fmk_encryption_method,
        }
    }

    fn to_fb<'a>(
        &self,
        fbb: &mut FlatBufferBuilder<'a>,
    ) -> Result<WIPOffset<fb::RecipientRecord<'a>>, SerializeError> {
        let (capsule_type, capsule) = match &self.capsule {
            Capsule::Symmetric(c) => symmetric_capsule_to_fb(fbb, c),
            Capsule::Password(c) => password_capsule_to_fb(fbb, c)?,
            Capsule::Unsupported => return Err(SerializeError::UnsupportedCapsule),
        };

        let fmk_encryption_method = match self.fmk_encryption_method {
            FmkEncryptionMethod::Xor => fb::FMKEncryptionMethod::XOR,
            FmkEncryptionMethod::Unknown => {
                return Err(SerializeError::UnknownFmkEncryptionMethod);
            }
        };

        let key_label = fbb.create_string(&self.key_label);
        let encrypted_fmk = fbb.create_vector(&self.encrypted_fmk);
        Ok(fb::RecipientRecord::create(
            fbb,
            &fb::RecipientRecordArgs {
                capsule_type,
                capsule: Some(capsule),
                key_label: Some(key_label),
                encrypted_fmk: Some(encrypted_fmk),
                fmk_encryption_method,
            },
        ))
    }
}

fn symmetric_capsule_from_fb(capsule: fb_rec::SymmetricKeyCapsule<'_>) -> Capsule {
    Capsule::Symmetric(SymmetricKeyCapsule {
        salt: capsule.salt().bytes().to_vec(),
    })
}

fn symmetric_capsule_to_fb(
    fbb: &mut FlatBufferBuilder<'_>,
    capsule: &SymmetricKeyCapsule,
) -> (fb::Capsule, WIPOffset<UnionWIPOffset>) {
    let salt = fbb.create_vector(&capsule.salt);
    let offset = fb_rec::SymmetricKeyCapsule::create(
        fbb,
        &fb_rec::SymmetricKeyCapsuleArgs { salt: Some(salt) },
    );
    (
        fb::Capsule::recipients_SymmetricKeyCapsule,
        offset.as_union_value(),
    )
}

fn password_capsule_from_fb(capsule: fb_rec::PBKDF2Capsule<'_>) -> Capsule {
    if capsule.kdf_algorithm_identifier() != fb_rec::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256 {
        return Capsule::Unsupported;
    }
    let kdf_iterations = match u32::try_from(capsule.kdf_iterations()) {
        Ok(n) if n > 0 => n,
        _ => return Capsule::Unsupported,
    };

    Capsule::Password(Pbkdf2Capsule {
        salt: capsule.salt().bytes().to_vec(),
        password_salt: capsule.password_salt().bytes().to_vec(),
        kdf_iterations,
    })
}

fn password_capsule_to_fb(
    fbb: &mut FlatBufferBuilder<'_>,
    capsule: &Pbkdf2Capsule,
) -> Result<(fb::Capsule, WIPOffset<UnionWIPOffset>), SerializeError> {
    let kdf_iterations = i32::try_from(capsule.kdf_iterations)
        .ok()
        .filter(|&n| n > 0)
        .ok_or(SerializeError::UnsupportedCapsule)?;

    let salt = fbb.create_vector(&capsule.salt);
    let password_salt = fbb.create_vector(&capsule.password_salt);
    let offset = fb_rec::PBKDF2Capsule::create(
        fbb,
        &fb_rec::PBKDF2CapsuleArgs {
            salt: Some(salt),
            password_salt: Some(password_salt),
            kdf_algorithm_identifier: fb_rec::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256,
            kdf_iterations,
        },
    );
    Ok((
        fb::Capsule::recipients_PBKDF2Capsule,
        offset.as_union_value(),
    ))
}
