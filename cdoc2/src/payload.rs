use crate::aead_stream::{AeadError, Decryptor, Encryptor, NONCE_LEN, TAG_LEN};
use crate::crypto::{AuthenticatedHeader, FMK_LEN, HMAC_LEN, derive_cek};
use crate::header::{Header, PayloadEncryptionMethod};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("unsupported payload encryption method")]
    UnsupportedPayloadEncryptionMethod,
    #[error("payload is too short")]
    TooShort,
    #[error("payload decryption failed: corrupted or tampered payload")]
    DecryptionFailed,
}

pub(crate) fn check_payload_encryption_method(header: &Header) -> Result<(), PayloadError> {
    if header.payload_encryption_method != PayloadEncryptionMethod::ChaCha20Poly1305 {
        return Err(PayloadError::UnsupportedPayloadEncryptionMethod);
    }
    Ok(())
}

fn payload_aad(header_bytes: &[u8], header_hmac: &[u8; HMAC_LEN]) -> Vec<u8> {
    [
        b"CDOC20payload".as_slice(),
        header_bytes,
        header_hmac.as_slice(),
    ]
    .concat()
}

pub(crate) fn encrypt_payload(
    fmk: &[u8; FMK_LEN],
    header_bytes: &[u8],
    header_hmac: &[u8; HMAC_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let mut encryptor = Encryptor::new(
        &derive_cek(fmk),
        nonce,
        &payload_aad(header_bytes, header_hmac),
    );
    let mut payload = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(plaintext);
    encryptor.encrypt(&mut payload[NONCE_LEN..])?;
    payload.extend_from_slice(&encryptor.finalize());
    Ok(payload)
}

pub(crate) fn decrypt_payload(
    header: &AuthenticatedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, PayloadError> {
    let (nonce, rest) = payload
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(PayloadError::TooShort)?;
    let (ciphertext, tag) = rest
        .split_last_chunk::<TAG_LEN>()
        .ok_or(PayloadError::TooShort)?;

    let mut decryptor = Decryptor::new(
        &derive_cek(header.fmk()),
        nonce,
        &payload_aad(header.header_bytes(), header.header_hmac()),
    );
    let mut plaintext = ciphertext.to_vec();
    decryptor
        .decrypt(&mut plaintext)
        .map_err(|_| PayloadError::DecryptionFailed)?;
    decryptor
        .verify(tag)
        .map_err(|_| PayloadError::DecryptionFailed)?;
    Ok(plaintext)
}
