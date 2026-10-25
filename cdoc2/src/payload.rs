use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::IoError;
use crate::aead_stream::{AeadError, Decryptor, Encryptor, NONCE_LEN, TAG_LEN, Verifier};
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
    #[error("cannot read payload: {0}")]
    Read(IoError),
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

pub(crate) struct PayloadWriter<W> {
    inner: W,
    encryptor: Encryptor,
    buf: Vec<u8>,
}

impl<W: Write> PayloadWriter<W> {
    pub(crate) fn new(
        fmk: &[u8; FMK_LEN],
        header_bytes: &[u8],
        header_hmac: &[u8; HMAC_LEN],
        nonce: &[u8; NONCE_LEN],
        mut inner: W,
    ) -> io::Result<Self> {
        inner.write_all(nonce)?;
        let aad = payload_aad(header_bytes, header_hmac);
        Ok(PayloadWriter {
            inner,
            encryptor: Encryptor::new(&derive_cek(fmk), nonce, &aad),
            buf: Vec::new(),
        })
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        let tag = self.encryptor.finalize();
        self.inner.write_all(&tag)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for PayloadWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.clear();
        self.buf.extend_from_slice(data);
        self.encryptor
            .encrypt(&mut self.buf)
            .map_err(io::Error::other)?;
        self.inner.write_all(&self.buf)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

const READ_SIZE: usize = 64 * 1024;

struct CiphertextReader<R> {
    inner: R,
    held: Vec<u8>,
}

impl<R: Read> CiphertextReader<R> {
    fn new(mut inner: R) -> Result<([u8; NONCE_LEN], Self), PayloadError> {
        let nonce = read_array(&mut inner)?;
        let held = Vec::with_capacity(READ_SIZE + TAG_LEN);
        Ok((nonce, CiphertextReader { inner, held }))
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, PayloadError> {
        let wanted = out.len() + TAG_LEN;
        if self.held.len() < wanted {
            let start = self.held.len();
            self.held.resize(wanted, 0);
            let n = fill(&mut self.inner, &mut self.held[start..])?;
            self.held.truncate(start + n);
        }
        let n = self.held.len().saturating_sub(TAG_LEN).min(out.len());
        out[..n].copy_from_slice(&self.held[..n]);
        self.held.drain(..n);
        Ok(n)
    }

    // Only valid once `read` has returned 0.
    fn tag(self) -> Result<[u8; TAG_LEN], PayloadError> {
        self.held
            .as_slice()
            .try_into()
            .map_err(|_| PayloadError::TooShort)
    }
}

pub(crate) struct PayloadReader<R> {
    ciphertext: CiphertextReader<R>,
    decryptor: Decryptor,
}

impl<R: Read> PayloadReader<R> {
    pub(crate) fn new(header: &AuthenticatedHeader, payload: R) -> Result<Self, PayloadError> {
        let (nonce, ciphertext) = CiphertextReader::new(payload)?;
        Ok(PayloadReader {
            ciphertext,
            decryptor: Decryptor::new(&derive_cek(header.fmk()), &nonce, &header_aad(header)),
        })
    }

    pub(crate) fn finish(mut self) -> Result<(), PayloadError> {
        let mut buf = vec![0; READ_SIZE];
        while self.read_payload(&mut buf)? > 0 {}
        let tag = self.ciphertext.tag()?;
        self.decryptor.verify(&tag).map_err(decryption_failed)
    }

    fn read_payload(&mut self, out: &mut [u8]) -> Result<usize, PayloadError> {
        let n = self.ciphertext.read(out)?;
        self.decryptor
            .decrypt(&mut out[..n])
            .map_err(decryption_failed)?;
        Ok(n)
    }
}

impl<R: Read> Read for PayloadReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.read_payload(out).map_err(io::Error::other)
    }
}

pub(crate) fn verify_payload(
    header: &AuthenticatedHeader,
    payload: &mut (impl Read + Seek),
) -> Result<(), PayloadError> {
    let start = payload.stream_position().map_err(read_error)?;
    let (nonce, mut ciphertext) = CiphertextReader::new(payload.by_ref())?;

    let mut verifier = Verifier::new(&derive_cek(header.fmk()), &nonce, &header_aad(header));
    let mut buf = vec![0; READ_SIZE];
    while let n @ 1.. = ciphertext.read(&mut buf)? {
        verifier.update(&buf[..n]).map_err(decryption_failed)?;
    }
    verifier
        .verify(&ciphertext.tag()?)
        .map_err(decryption_failed)?;

    payload.seek(SeekFrom::Start(start)).map_err(read_error)?;
    Ok(())
}

fn header_aad(header: &AuthenticatedHeader) -> Vec<u8> {
    payload_aad(header.header_bytes(), header.header_hmac())
}

fn fill(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, PayloadError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(read_error(e)),
        }
    }
    Ok(filled)
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], PayloadError> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(bytes)
}

fn read_error(e: io::Error) -> PayloadError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        PayloadError::TooShort
    } else {
        PayloadError::Read(e.into())
    }
}

fn decryption_failed(_: AeadError) -> PayloadError {
    PayloadError::DecryptionFailed
}
