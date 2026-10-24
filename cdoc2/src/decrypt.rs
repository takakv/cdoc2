use crate::archive::{self, File, UnpackError};
use crate::capsule::ecc::{EcSecretKey, EccKekError};
use crate::capsule::{Capsule, decrypt_fmk};
use crate::container::Container;
use crate::crypto::{FMK_LEN, authenticate_header};
use crate::header::{FmkEncryptionMethod, RecipientRecord};
use crate::payload::{PayloadError, check_payload_encryption_method, decrypt_payload};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    #[error("key type does not match the recipient's capsule type")]
    KeyTypeMismatch,
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
    let kek = derive_kek(container, record, key)?;
    decrypt_with_kek(container, record, &kek, max_size)
}

fn derive_kek(
    container: &Container,
    record: &RecipientRecord,
    key: &DecryptionKey,
) -> Result<[u8; FMK_LEN], DecryptError> {
    check_encryption_methods(container, record)?;
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
        _ => Err(DecryptError::KeyTypeMismatch),
    }
}

fn check_encryption_methods(
    container: &Container,
    record: &RecipientRecord,
) -> Result<(), DecryptError> {
    if record.fmk_encryption_method != FmkEncryptionMethod::Xor {
        return Err(DecryptError::UnsupportedFmkEncryptionMethod);
    }
    check_payload_encryption_method(&container.head.header)?;
    Ok(())
}

fn decrypt_with_kek(
    container: &Container,
    record: &RecipientRecord,
    kek: &[u8; FMK_LEN],
    max_size: u64,
) -> Result<Vec<File>, DecryptError> {
    let encrypted_fmk = record
        .encrypted_fmk
        .as_slice()
        .try_into()
        .map_err(|_| DecryptError::InvalidEncryptedFmkLength(record.encrypted_fmk.len()))?;
    let fmk = decrypt_fmk(encrypted_fmk, kek);
    let header = authenticate_header(
        fmk,
        &container.head.header_bytes,
        &container.head.header_hmac,
    )
    .map_err(|_| DecryptError::HmacMismatch)?;
    let payload = decrypt_payload(&header, container.payload)?;
    Ok(archive::unpack(&payload, max_size)?)
}
