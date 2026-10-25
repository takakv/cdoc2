#[allow(dead_code, unused_imports, clippy::all)]
#[rustfmt::skip]
mod generated;

mod fb;

use crate::capsule::Capsule;
use crate::capsule::ecc::{EcPublicKey, EccPublicKeyCapsule};

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
    pub(crate) fn parse(bytes: &[u8]) -> Result<Header, HeaderError> {
        fb::header_from_bytes(bytes)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, SerializeError> {
        fb::header_to_bytes(self)
    }
}

impl RecipientRecord {
    pub fn is_for_public_key(&self, public_key: &EcPublicKey) -> bool {
        let public_key = public_key.to_sec1_bytes();
        match &self.capsule {
            Capsule::Ecc(capsule) => capsule.recipient_public_key == public_key,
            Capsule::KeyServer(capsule) => capsule.recipient_public_key == public_key,
            Capsule::Symmetric(_) | Capsule::Password(_) | Capsule::Unsupported => false,
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
