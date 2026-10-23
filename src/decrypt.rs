use crate::crypto::FMK_LEN;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
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
