use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{KeyInit, Mac};

use crate::crypto::{FMK_LEN, Hkdf, Hmac};
use crate::decrypt::DecryptError;
use crate::header::{Header, HeaderError, PayloadEncryptionMethod};

const PRELUDE: &[u8; 4] = b"CDOC";
const VERSION: u8 = 2;
const MAX_HEADER_LEN: usize = 1 << 20;
const HMAC_LEN: usize = 32;
const HHK_LEN: usize = 32;
const CEK_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct Container<'a> {
    pub header: Header,
    pub header_bytes: &'a [u8],
    pub header_hmac: &'a [u8; HMAC_LEN],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContainerError {
    #[error("not a CDOC2 container")]
    NotCdoc2,
    #[error("unsupported CDOC version: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid header length")]
    InvalidHeaderLength,
    #[error("container is truncated")]
    Truncated,
    #[error(transparent)]
    Header(#[from] HeaderError),
}

impl<'a> Container<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ContainerError> {
        let rest = bytes
            .strip_prefix(PRELUDE)
            .ok_or(ContainerError::NotCdoc2)?;

        let (&version, rest) = rest.split_first().ok_or(ContainerError::Truncated)?;
        if version != VERSION {
            return Err(ContainerError::UnsupportedVersion(version));
        }

        let (header_len, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(ContainerError::Truncated)?;
        let header_len = usize::try_from(i32::from_be_bytes(*header_len))
            .ok()
            .filter(|&len| len <= MAX_HEADER_LEN)
            .ok_or(ContainerError::InvalidHeaderLength)?;

        let (header_bytes, rest) = rest
            .split_at_checked(header_len)
            .ok_or(ContainerError::Truncated)?;
        let (header_hmac, payload) = rest
            .split_first_chunk::<HMAC_LEN>()
            .ok_or(ContainerError::Truncated)?;

        let header = Header::parse(header_bytes)?;

        Ok(Container {
            header,
            header_bytes,
            header_hmac,
            payload,
        })
    }

    pub fn verify_header_hmac(&self, fmk: &[u8; FMK_LEN]) -> Result<(), DecryptError> {
        header_mac(fmk, self.header_bytes)
            .verify_slice(self.header_hmac)
            .map_err(|_| DecryptError::HmacMismatch)
    }

    pub fn decrypt_payload(&self, fmk: &[u8; FMK_LEN]) -> Result<Vec<u8>, DecryptError> {
        if self.header.payload_encryption_method != PayloadEncryptionMethod::ChaCha20Poly1305 {
            return Err(DecryptError::UnsupportedPayloadEncryptionMethod);
        }

        self.verify_header_hmac(fmk)?;

        if self.payload.len() < NONCE_LEN + TAG_LEN {
            return Err(DecryptError::PayloadTooShort);
        }

        let cipher = payload_cipher(fmk);
        let (nonce, ciphertext) = self
            .payload
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(DecryptError::PayloadTooShort)?;

        cipher
            .decrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: &payload_aad(self.header_bytes, self.header_hmac),
                },
            )
            .map_err(|_| DecryptError::PayloadDecryptionFailed)
    }
}

fn header_mac(fmk: &[u8; FMK_LEN], header_bytes: &[u8]) -> Hmac {
    let hhk = derive_hhk(fmk);
    let mut mac = Hmac::new_from_slice(&hhk).expect("HMAC should accept keys of any size");
    mac.update(header_bytes);
    mac
}

pub(crate) fn compute_header_hmac(fmk: &[u8; FMK_LEN], header_bytes: &[u8]) -> [u8; HMAC_LEN] {
    header_mac(fmk, header_bytes).finalize().into_bytes().into()
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

pub(crate) fn write_container(
    header_bytes: &[u8],
    header_hmac: &[u8; HMAC_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, ContainerError> {
    if header_bytes.len() > MAX_HEADER_LEN {
        return Err(ContainerError::InvalidHeaderLength);
    }
    let header_len =
        i32::try_from(header_bytes.len()).expect("MAX_HEADER_LEN should fit in an i32");

    let parts: [&[u8]; 6] = [
        PRELUDE,
        &[VERSION],
        &header_len.to_be_bytes(),
        header_bytes,
        header_hmac,
        payload,
    ];
    Ok(parts.concat())
}

fn derive_hhk(fmk: &[u8; FMK_LEN]) -> [u8; HHK_LEN] {
    expand_fmk(fmk, b"CDOC20hmac")
}

fn derive_cek(fmk: &[u8; FMK_LEN]) -> [u8; CEK_LEN] {
    expand_fmk(fmk, b"CDOC20cek")
}

fn expand_fmk<const N: usize>(fmk: &[u8; FMK_LEN], info: &[u8]) -> [u8; N] {
    let mut key = [0u8; N];
    let hk = Hkdf::from_prk(fmk).expect("FMK should be long enough to be an HKDF PRK");
    hk.expand(info, &mut key)
        .expect("key should be short enough for HKDF-Expand");
    key
}
