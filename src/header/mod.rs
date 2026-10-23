#[allow(dead_code, unused_imports, clippy::all)]
#[rustfmt::skip]
mod generated;

use crate::capsule::Capsule;

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
