use std::io::{Cursor, Read, Seek};

use crate::archive::{self, File, Sink, UnpackError};
use crate::capsule::ecc::{EcSecretKey, EccKekError};
use crate::capsule::{Capsule, decrypt_fmk};
use crate::container::{Container, ContainerHead};
use crate::crypto::{AuthenticatedHeader, FMK_LEN, authenticate_header};
use crate::header::{FmkEncryptionMethod, RecipientRecord};
use crate::payload::{
    PayloadError, PayloadReader, check_payload_encryption_method, verify_payload,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    #[error("key type does not match the recipient's capsule type")]
    KeyTypeMismatch,
    #[error("the recipient's key capsule must first be fetched from its key server")]
    CapsuleNotFetched,
    #[error("unsupported FMK encryption method")]
    UnsupportedFmkEncryptionMethod,
    #[error("encrypted FMK must be {FMK_LEN} bytes, got {0}")]
    InvalidEncryptedFmkLength(usize),
    #[error("header HMAC mismatch: wrong key or corrupted file")]
    HmacMismatch,
    #[error(transparent)]
    EccKek(#[from] EccKekError),
    #[error(transparent)]
    Payload(#[from] PayloadError),
    #[error(transparent)]
    Unpack(#[from] UnpackError),
}

#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum DecryptionKey<'a> {
    Symmetric(&'a [u8]),
    Password(&'a str),
    EcSecretKey(&'a EcSecretKey),
    EcdhSharedSecret(&'a [u8]),
}

pub fn decrypt(
    container: &Container,
    record: &RecipientRecord,
    key: &DecryptionKey,
    max_size: u64,
) -> Result<Vec<File>, DecryptError> {
    let mut files = Vec::new();
    decrypt_into(
        &container.head,
        record,
        key,
        Cursor::new(container.payload),
        max_size,
        &mut files,
    )?;
    Ok(files)
}

pub fn decrypt_into(
    head: &ContainerHead,
    record: &RecipientRecord,
    key: &DecryptionKey,
    mut payload: impl Read + Seek,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), DecryptError> {
    let header = authenticate(head, record, key)?;
    verify_payload(&header, &mut payload)?;
    decrypt_payload(&header, payload, max_size, sink)
}

pub(crate) fn decrypt_payload(
    header: &AuthenticatedHeader,
    payload: impl Read + Seek,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), DecryptError> {
    let mut payload = PayloadReader::new(header, payload)?;
    let unpacked = archive::unpack(&mut payload, max_size, sink);
    // The payload may be unverified, or may have changed since it was verified, so the tag
    // must take priority over unpacking errors.
    payload.finish()?;
    Ok(unpacked?)
}

pub(crate) fn authenticate<'a>(
    head: &'a ContainerHead,
    record: &RecipientRecord,
    key: &DecryptionKey,
) -> Result<AuthenticatedHeader<'a>, DecryptError> {
    let kek = derive_kek(head, record, key)?;
    let encrypted_fmk = record
        .encrypted_fmk
        .as_slice()
        .try_into()
        .map_err(|_| DecryptError::InvalidEncryptedFmkLength(record.encrypted_fmk.len()))?;
    let fmk = decrypt_fmk(encrypted_fmk, &kek);
    authenticate_header(fmk, &head.header_bytes, &head.header_hmac)
        .map_err(|_| DecryptError::HmacMismatch)
}

fn derive_kek(
    head: &ContainerHead,
    record: &RecipientRecord,
    key: &DecryptionKey,
) -> Result<[u8; FMK_LEN], DecryptError> {
    check_encryption_methods(head, record)?;
    match (&record.capsule, *key) {
        (Capsule::Symmetric(capsule), DecryptionKey::Symmetric(key)) => {
            Ok(capsule.derive_kek(key, &record.key_label))
        }
        (Capsule::Password(capsule), DecryptionKey::Password(password)) => {
            Ok(capsule.derive_kek(password, &record.key_label))
        }
        (Capsule::Ecc(capsule), DecryptionKey::EcSecretKey(secret_key)) => {
            Ok(capsule.derive_kek(secret_key)?)
        }
        (Capsule::Ecc(capsule), DecryptionKey::EcdhSharedSecret(shared_secret)) => {
            Ok(capsule.derive_kek_from_shared_secret(shared_secret)?)
        }
        (Capsule::KeyServer(_), _) => Err(DecryptError::CapsuleNotFetched),
        _ => Err(DecryptError::KeyTypeMismatch),
    }
}

fn check_encryption_methods(
    head: &ContainerHead,
    record: &RecipientRecord,
) -> Result<(), DecryptError> {
    if record.fmk_encryption_method != FmkEncryptionMethod::Xor {
        return Err(DecryptError::UnsupportedFmkEncryptionMethod);
    }
    check_payload_encryption_method(&head.header)?;
    Ok(())
}
