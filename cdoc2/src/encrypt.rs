use std::collections::HashSet;

use crate::archive::{File, FileNameError, pack};
use crate::capsule::{password, symmetric};
use crate::container::{NONCE_LEN, compute_header_hmac, encrypt_payload, write_container};
use crate::crypto::{generate_fmk, random_bytes};
use crate::header::{Header, PayloadEncryptionMethod};

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Recipient<'a> {
    Symmetric {
        key_label: &'a str,
        key: &'a [u8],
    },
    Password {
        key_label: &'a str,
        password: &'a str,
    },
}

impl Recipient<'_> {
    pub fn key_label(&self) -> &str {
        match *self {
            Recipient::Symmetric { key_label, .. } | Recipient::Password { key_label, .. } => {
                key_label
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncryptError {
    #[error("at least one recipient is required")]
    NoRecipients,
    #[error("every recipient needs a key label")]
    EmptyKeyLabel,
    #[error("key label {0:?} is used by more than one recipient")]
    DuplicateKeyLabel(String),
    #[error(transparent)]
    FileName(#[from] FileNameError),
    #[error("the header is too large (too many recipients or too long key labels)")]
    HeaderTooLarge,
    #[error("the files are too large to encrypt")]
    PayloadTooLarge,
    #[error("could not generate random bytes: {0}")]
    Random(String),
}

pub fn encrypt(files: &[File], recipients: &[Recipient]) -> Result<Vec<u8>, EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients);
    }
    check_key_labels(recipients)?;

    let tar = pack(files)?;
    let fmk = generate_fmk().map_err(random_error)?;

    let mut records = Vec::with_capacity(recipients.len());
    for r in recipients {
        let record = match *r {
            Recipient::Symmetric { key_label, key } => {
                symmetric::recipient_record(key, key_label, &fmk)
            }
            Recipient::Password {
                key_label,
                password,
            } => password::recipient_record(password, key_label, &fmk),
        };
        records.push(record.map_err(random_error)?);
    }

    let header = Header {
        recipients: records,
        payload_encryption_method: PayloadEncryptionMethod::ChaCha20Poly1305,
    };
    let header_bytes = header
        .to_bytes()
        .expect("headers built for encryption should be serializable");
    let header_hmac = compute_header_hmac(&fmk, &header_bytes);

    let nonce = random_bytes::<NONCE_LEN>().map_err(random_error)?;
    let payload = encrypt_payload(&fmk, &header_bytes, &header_hmac, &nonce, &tar)
        .map_err(|_| EncryptError::PayloadTooLarge)?;

    write_container(&header_bytes, &header_hmac, &payload).map_err(|_| EncryptError::HeaderTooLarge)
}

fn random_error(e: getrandom::Error) -> EncryptError {
    EncryptError::Random(e.to_string())
}

fn check_key_labels(recipients: &[Recipient]) -> Result<(), EncryptError> {
    let mut seen = HashSet::new();
    for recipient in recipients {
        let label = recipient.key_label();
        if label.is_empty() {
            return Err(EncryptError::EmptyKeyLabel);
        }
        if !seen.insert(label) {
            return Err(EncryptError::DuplicateKeyLabel(label.to_owned()));
        }
    }
    Ok(())
}
