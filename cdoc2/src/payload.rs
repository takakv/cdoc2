use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use crate::crypto::{AuthenticatedHeader, FMK_LEN, HMAC_LEN, derive_cek};
use crate::header::{Header, PayloadEncryptionMethod};

pub(crate) const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

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

fn payload_cipher(fmk: &[u8; FMK_LEN]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(derive_cek(fmk)))
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
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let ciphertext = payload_cipher(fmk).encrypt(
        &Nonce::from(*nonce),
        Payload {
            msg: plaintext,
            aad: &payload_aad(header_bytes, header_hmac),
        },
    )?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}

pub(crate) fn decrypt_payload(
    header: &AuthenticatedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, PayloadError> {
    let (nonce, ciphertext) = payload
        .split_first_chunk::<NONCE_LEN>()
        .filter(|(_, ciphertext)| ciphertext.len() >= TAG_LEN)
        .ok_or(PayloadError::TooShort)?;

    payload_cipher(header.fmk())
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &payload_aad(header.header_bytes(), header.header_hmac()),
            },
        )
        .map_err(|_| PayloadError::DecryptionFailed)
}
