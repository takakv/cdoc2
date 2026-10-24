use crate::archive::{self, File, UnpackError};
use crate::capsule::{Capsule, decrypt_fmk};
use crate::container::Container;
use crate::crypto::FMK_LEN;
use crate::header::{FmkEncryptionMethod, RecipientRecord};

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
    #[error("unsupported payload encryption method")]
    UnsupportedPayloadEncryptionMethod,
    #[error("payload is too short")]
    PayloadTooShort,
    #[error("payload decryption failed: corrupted or tampered payload")]
    PayloadDecryptionFailed,
    #[error(transparent)]
    Unpack(#[from] UnpackError),
}

pub fn decrypt_with_symmetric_key(
    container: &Container,
    record: &RecipientRecord,
    key: &[u8],
    max_size: u64,
) -> Result<Vec<File>, DecryptError> {
    let Capsule::Symmetric(capsule) = &record.capsule else {
        return Err(DecryptError::KeyTypeMismatch);
    };
    check_fmk_encryption_method(record)?;
    let kek = capsule.derive_kek(key, &record.key_label);
    decrypt_with_kek(container, record, &kek, max_size)
}

pub fn decrypt_with_password(
    container: &Container,
    record: &RecipientRecord,
    password: &str,
    max_size: u64,
) -> Result<Vec<File>, DecryptError> {
    let Capsule::Password(capsule) = &record.capsule else {
        return Err(DecryptError::KeyTypeMismatch);
    };
    check_fmk_encryption_method(record)?;
    let kek = capsule.derive_kek(password, &record.key_label);
    decrypt_with_kek(container, record, &kek, max_size)
}

fn check_fmk_encryption_method(record: &RecipientRecord) -> Result<(), DecryptError> {
    if record.fmk_encryption_method != FmkEncryptionMethod::Xor {
        return Err(DecryptError::UnsupportedFmkEncryptionMethod);
    }
    Ok(())
}

fn decrypt_with_kek(
    container: &Container,
    record: &RecipientRecord,
    kek: &[u8; FMK_LEN],
    max_size: u64,
) -> Result<Vec<File>, DecryptError> {
    let fmk = decrypt_fmk(&record.encrypted_fmk, kek)?;
    let payload = container.decrypt_payload(&fmk)?;
    Ok(archive::unpack(&payload, max_size)?)
}
