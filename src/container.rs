use crate::header::{Header, HeaderError};

const PRELUDE: &[u8; 4] = b"CDOC";
const VERSION: u8 = 2;
const MAX_HEADER_LEN: usize = 1 << 20;
const HMAC_LEN: usize = 32;

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
}
