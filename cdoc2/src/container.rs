//! Reading containers.

use std::io::{self, Read};

use crate::IoError;
use crate::crypto::HMAC_LEN;
use crate::header::{Header, HeaderError};

const PRELUDE: &[u8; 4] = b"CDOC";
const VERSION: u8 = 2;
const MAX_HEADER_LEN: usize = 1 << 20;

/// The part of a container before the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHead {
    /// The parsed header. It isn't authenticated until decryption checks its HMAC.
    pub header: Header,
    pub(crate) header_bytes: Vec<u8>,
    pub(crate) header_hmac: [u8; HMAC_LEN],
}

/// A container held in memory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Container<'a> {
    pub head: ContainerHead,
    pub payload: &'a [u8],
}

/// An error reading a container's head.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContainerError {
    /// The data doesn't start with `CDOC`.
    #[error("not a CDOC2 container")]
    NotCdoc2,
    /// The version byte isn't 2.
    #[error("unsupported CDOC version: {0}")]
    UnsupportedVersion(u8),
    /// The header length is negative or larger than 1 MiB.
    #[error("invalid header length")]
    InvalidHeaderLength,
    /// The data ends partway through the head.
    #[error("container is truncated")]
    Truncated,
    /// The reader returned an error.
    #[error("cannot read container: {0}")]
    Read(IoError),
    /// The header can't be parsed.
    #[error(transparent)]
    Header(#[from] HeaderError),
}

impl ContainerHead {
    /// Reads a container's head from `reader`.
    ///
    /// Leaves `reader` at the start of the payload.
    ///
    /// # Errors
    ///
    /// Returns an error if `reader` fails, or the data doesn't start with a valid container head.
    pub fn read(reader: &mut impl Read) -> Result<Self, ContainerError> {
        let mut prelude = Vec::with_capacity(PRELUDE.len());
        reader
            .by_ref()
            .take(PRELUDE.len() as u64)
            .read_to_end(&mut prelude)
            .map_err(read_error)?;
        if prelude != PRELUDE {
            return Err(ContainerError::NotCdoc2);
        }

        let [version] = read_array(reader)?;
        if version != VERSION {
            return Err(ContainerError::UnsupportedVersion(version));
        }

        let header_len = usize::try_from(i32::from_be_bytes(read_array(reader)?))
            .ok()
            .filter(|&len| len <= MAX_HEADER_LEN)
            .ok_or(ContainerError::InvalidHeaderLength)?;

        let mut header_bytes = vec![0; header_len];
        reader.read_exact(&mut header_bytes).map_err(read_error)?;
        let header_hmac = read_array(reader)?;

        let header = Header::parse(&header_bytes)?;

        Ok(ContainerHead {
            header,
            header_bytes,
            header_hmac,
        })
    }
}

impl<'a> Container<'a> {
    /// Parses a container held in memory.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` doesn't start with a valid container head.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ContainerError> {
        let mut payload = bytes;
        let head = ContainerHead::read(&mut payload)?;
        Ok(Container { head, payload })
    }
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], ContainerError> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes).map_err(read_error)?;
    Ok(bytes)
}

fn read_error(e: io::Error) -> ContainerError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        ContainerError::Truncated
    } else {
        ContainerError::Read(e.into())
    }
}

pub(crate) fn encode_head(
    header_bytes: &[u8],
    header_hmac: &[u8; HMAC_LEN],
) -> Result<Vec<u8>, ContainerError> {
    if header_bytes.len() > MAX_HEADER_LEN {
        return Err(ContainerError::InvalidHeaderLength);
    }
    let header_len =
        i32::try_from(header_bytes.len()).expect("MAX_HEADER_LEN should fit in an i32");

    let parts: [&[u8]; 5] = [
        PRELUDE,
        &[VERSION],
        &header_len.to_be_bytes(),
        header_bytes,
        header_hmac,
    ];
    Ok(parts.concat())
}
