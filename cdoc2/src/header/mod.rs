#[allow(dead_code, unused_imports, clippy::all)]
#[rustfmt::skip]
mod generated;

mod fb;

use crate::capsule::Capsule;
use crate::capsule::ecc::{EcPublicKey, EccPublicKeyCapsule};
use crate::crypto::FMK_LEN;
use crate::key_label;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub recipients: Vec<RecipientRecord>,
    pub(crate) payload_encryption_method: PayloadEncryptionMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecord {
    pub capsule: Capsule,
    pub key_label: String,
    pub(crate) encrypted_fmk: Vec<u8>,
    pub(crate) fmk_encryption_method: FmkEncryptionMethod,
}

#[derive(Debug, Clone, Copy)]
pub enum RecipientId<'a> {
    EcPublicKey(&'a EcPublicKey),
    Symmetric { label: &'a str },
    Password { label: &'a str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the container is not meant for this key")]
pub struct RecipientNotFound;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FmkEncryptionMethod {
    Xor,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadEncryptionMethod {
    ChaCha20Poly1305,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("malformed header: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SerializeError {
    #[error("cannot serialize an unsupported capsule")]
    UnsupportedCapsule,
    #[error("cannot serialize an unknown FMK encryption method")]
    UnknownFmkEncryptionMethod,
    #[error("cannot serialize an unknown payload encryption method")]
    UnknownPayloadEncryptionMethod,
}

impl Header {
    pub fn find_recipient(&self, id: RecipientId) -> Result<&RecipientRecord, RecipientNotFound> {
        self.recipients
            .iter()
            .find(|record| record.is_for(id))
            .ok_or(RecipientNotFound)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Header, HeaderError> {
        fb::header_from_bytes(bytes)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, SerializeError> {
        fb::header_to_bytes(self)
    }
}

impl RecipientRecord {
    pub(crate) fn new(
        capsule: Capsule,
        key_label: impl Into<String>,
        encrypted_fmk: [u8; FMK_LEN],
    ) -> RecipientRecord {
        RecipientRecord {
            capsule,
            key_label: key_label.into(),
            encrypted_fmk: encrypted_fmk.to_vec(),
            fmk_encryption_method: FmkEncryptionMethod::Xor,
        }
    }

    fn is_for(&self, id: RecipientId) -> bool {
        match (&self.capsule, id) {
            (Capsule::Ecc(capsule), RecipientId::EcPublicKey(key)) => {
                capsule.recipient_public_key == key.to_sec1_bytes()
            }
            (Capsule::KeyServer(capsule), RecipientId::EcPublicKey(key)) => {
                capsule.recipient_public_key == key.to_sec1_bytes()
            }
            (Capsule::Symmetric(_), RecipientId::Symmetric { label })
            | (Capsule::Password(_), RecipientId::Password { label }) => {
                key_label::matches(&self.key_label, label)
            }
            _ => false,
        }
    }

    pub fn with_sender_public_key(&self, sender_public_key: Vec<u8>) -> Option<RecipientRecord> {
        let Capsule::KeyServer(capsule) = &self.capsule else {
            return None;
        };
        Some(RecipientRecord {
            capsule: Capsule::Ecc(EccPublicKeyCapsule {
                curve: capsule.curve,
                recipient_public_key: capsule.recipient_public_key.clone(),
                sender_public_key,
            }),
            ..self.clone()
        })
    }
}
