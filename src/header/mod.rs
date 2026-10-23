#[allow(dead_code, unused_imports, clippy::all)]
#[rustfmt::skip]
mod generated;

use crate::capsule::Capsule;
use crate::capsule::symmetric::SymmetricKeyCapsule;
use generated::ee::cyber::cdoc_2::fbs::header as fb;

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

        let recipients = match header.recipients() {
            Some(records) => records.iter().map(RecipientRecord::from_fb).collect(),
            None => Vec::new(),
        };

        Ok(Header {
            recipients,
            payload_encryption_method,
        })
    }
}

impl RecipientRecord {
    fn from_fb(record: fb::RecipientRecord<'_>) -> RecipientRecord {
        let capsule = match record.capsule_as_recipients_symmetric_key_capsule() {
            Some(c) => Capsule::Symmetric(SymmetricKeyCapsule {
                salt: c.salt().bytes().to_vec(),
            }),
            None => Capsule::Unsupported,
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
}
