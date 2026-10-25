use std::collections::HashSet;
use std::io::{self, Read, Write};

use crate::IoError;
use crate::aead_stream::{AeadError, NONCE_LEN};
use crate::archive::{File, FileEntry, FileNameError, PackError, check_file_names, pack};
use crate::capsule::ecc;
use crate::capsule::key_server::CapsuleUpload;
use crate::capsule::{password, symmetric};
use crate::container::encode_head;
use crate::crypto::{FMK_LEN, compute_header_hmac, generate_fmk, random_bytes};
use crate::header::{Header, PayloadEncryptionMethod, RecipientRecord};
use crate::keys::EcPublicKey;
use crate::payload::PayloadWriter;

#[derive(derive_more::Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Recipient<'a> {
    Symmetric {
        key_label: &'a str,
        #[debug("[redacted]")]
        key: &'a [u8],
    },
    Password {
        key_label: &'a str,
        #[debug("[redacted]")]
        password: &'a str,
    },
    EcPublicKey {
        key_label: &'a str,
        public_key: &'a EcPublicKey,
    },
    KeyServer {
        key_label: &'a str,
        public_key: &'a EcPublicKey,
        keyserver_id: &'a str,
        /// The recipient certificate's expiry, in seconds since the Unix epoch.
        not_after: Option<u64>,
    },
}

impl Recipient<'_> {
    pub(crate) fn key_label(&self) -> &str {
        match *self {
            Recipient::Symmetric { key_label, .. }
            | Recipient::Password { key_label, .. }
            | Recipient::EcPublicKey { key_label, .. }
            | Recipient::KeyServer { key_label, .. } => key_label,
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
    #[error("the key for {0:?} must be at least {MIN_KEY_LEN} bytes")]
    KeyTooShort(String),
    #[error("the password for {0:?} must be at least {MIN_PASSWORD_CHARS} characters")]
    PasswordTooShort(String),
    #[error(transparent)]
    FileName(#[from] FileNameError),
    #[error("the header is too large (too many recipients or too long key labels)")]
    HeaderTooLarge,
    #[error("the files are too large to encrypt")]
    PayloadTooLarge,
    #[error("could not generate random bytes: {0}")]
    Random(String),
    #[error("cannot read {name:?}: {error}")]
    Read { name: String, error: IoError },
    #[error("{0:?} changed size while being read")]
    SizeChanged(String),
    #[error("cannot write container: {0}")]
    Write(IoError),
    #[error("the key capsule for {0:?} has not been uploaded")]
    CapsuleNotUploaded(String),
}

pub struct PreparedEncryption {
    fmk: [u8; FMK_LEN],
    records: Vec<PreparedRecord>,
}

enum PreparedRecord {
    Ready(RecipientRecord),
    Upload(CapsuleUpload),
}

pub fn encrypt(files: &[File], recipients: &[Recipient]) -> Result<Vec<u8>, EncryptError> {
    prepare(recipients)?.encrypt(files)
}

/// Calls `open(i)` once for each file, in order, and expects exactly `files[i].size` bytes from
/// it. The output is only a valid container if this returns `Ok`.
pub fn encrypt_into<R: Read>(
    files: &[FileEntry],
    open: impl FnMut(usize) -> io::Result<R>,
    recipients: &[Recipient],
    out: impl Write,
) -> Result<(), EncryptError> {
    prepare(recipients)?.encrypt_into(files, open, out)
}

/// Generates the key material for every recipient.
pub fn prepare(recipients: &[Recipient]) -> Result<PreparedEncryption, EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients);
    }
    check_recipients(recipients)?;

    let fmk = generate_fmk().map_err(random_error)?;

    let mut records = Vec::with_capacity(recipients.len());
    for r in recipients {
        let record = match *r {
            Recipient::Symmetric { key_label, key } => {
                symmetric::recipient_record(key, key_label, &fmk).map(PreparedRecord::Ready)
            }
            Recipient::Password {
                key_label,
                password,
            } => password::recipient_record(password, key_label, &fmk).map(PreparedRecord::Ready),
            Recipient::EcPublicKey {
                key_label,
                public_key,
            } => ecc::recipient_record(public_key, key_label, &fmk).map(PreparedRecord::Ready),
            Recipient::KeyServer {
                key_label,
                public_key,
                keyserver_id,
                not_after,
            } => CapsuleUpload::generate(public_key, key_label, keyserver_id, not_after, &fmk)
                .map(PreparedRecord::Upload),
        };
        records.push(record.map_err(random_error)?);
    }

    Ok(PreparedEncryption { fmk, records })
}

impl PreparedEncryption {
    pub fn capsule_uploads(&mut self) -> impl Iterator<Item = &mut CapsuleUpload> {
        self.records.iter_mut().filter_map(|record| match record {
            PreparedRecord::Upload(upload) => Some(upload),
            PreparedRecord::Ready(_) => None,
        })
    }

    pub fn encrypt(self, files: &[File]) -> Result<Vec<u8>, EncryptError> {
        let entries: Vec<FileEntry> = files.iter().map(FileEntry::from).collect();
        let mut container = Vec::new();
        self.encrypt_into(&entries, |i| Ok(files[i].data.as_slice()), &mut container)?;
        Ok(container)
    }

    pub fn encrypt_into<R: Read>(
        self,
        files: &[FileEntry],
        open: impl FnMut(usize) -> io::Result<R>,
        mut out: impl Write,
    ) -> Result<(), EncryptError> {
        check_file_names(files)?;

        let recipients = self
            .records
            .into_iter()
            .map(|record| match record {
                PreparedRecord::Ready(record) => Ok(record),
                PreparedRecord::Upload(upload) if upload.is_uploaded() => Ok(upload.into_record()),
                PreparedRecord::Upload(upload) => Err(EncryptError::CapsuleNotUploaded(
                    upload.key_label().to_owned(),
                )),
            })
            .collect::<Result<_, _>>()?;

        let header = Header {
            recipients,
            payload_encryption_method: PayloadEncryptionMethod::ChaCha20Poly1305,
        };
        let header_bytes = header.to_bytes();
        let header_hmac = compute_header_hmac(&self.fmk, &header_bytes);

        let head =
            encode_head(&header_bytes, &header_hmac).map_err(|_| EncryptError::HeaderTooLarge)?;

        let nonce = random_bytes::<NONCE_LEN>().map_err(random_error)?;
        out.write_all(&head).map_err(write_error)?;
        let payload = PayloadWriter::new(&self.fmk, &header_bytes, &header_hmac, &nonce, out)
            .map_err(write_error)?;
        let payload = pack(files, open, payload).map_err(pack_error)?;
        payload
            .finish()
            .and_then(|mut out| out.flush())
            .map_err(write_error)
    }
}

fn random_error(e: getrandom::Error) -> EncryptError {
    EncryptError::Random(e.to_string())
}

fn pack_error(e: PackError) -> EncryptError {
    match e {
        PackError::Read { name, error } => EncryptError::Read {
            name,
            error: error.into(),
        },
        PackError::SizeChanged(name) => EncryptError::SizeChanged(name),
        PackError::Write(error) => write_error(error),
    }
}

fn write_error(e: io::Error) -> EncryptError {
    if e.get_ref().is_some_and(|e| e.is::<AeadError>()) {
        EncryptError::PayloadTooLarge
    } else {
        EncryptError::Write(e.into())
    }
}

const MIN_KEY_LEN: usize = 32;
const MIN_PASSWORD_CHARS: usize = 20;

fn check_recipients(recipients: &[Recipient]) -> Result<(), EncryptError> {
    let mut seen = HashSet::new();
    for recipient in recipients {
        let label = recipient.key_label();
        if label.is_empty() {
            return Err(EncryptError::EmptyKeyLabel);
        }
        if !seen.insert(label) {
            return Err(EncryptError::DuplicateKeyLabel(label.to_owned()));
        }
        match *recipient {
            Recipient::Symmetric { key, .. } if key.len() < MIN_KEY_LEN => {
                return Err(EncryptError::KeyTooShort(label.to_owned()));
            }
            Recipient::Password { password, .. }
                if password.chars().count() < MIN_PASSWORD_CHARS =>
            {
                return Err(EncryptError::PasswordTooShort(label.to_owned()));
            }
            _ => {}
        }
    }
    Ok(())
}
