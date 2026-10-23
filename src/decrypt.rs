use crate::capsule::Capsule;
use crate::capsule::symmetric::decrypt_fmk;
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
}

pub fn decrypt_with_symmetric_key(
    container: &Container,
    record: &RecipientRecord,
    key: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let Capsule::Symmetric(capsule) = &record.capsule else {
        return Err(DecryptError::KeyTypeMismatch);
    };
    if record.fmk_encryption_method != FmkEncryptionMethod::Xor {
        return Err(DecryptError::UnsupportedFmkEncryptionMethod);
    }

    let kek = capsule.derive_kek(key, &record.key_label);
    let fmk = decrypt_fmk(&record.encrypted_fmk, &kek)?;
    container.decrypt_payload(&fmk)
}
