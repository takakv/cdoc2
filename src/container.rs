use hmac::{KeyInit, Mac};

use crate::crypto::{FMK_LEN, Hkdf, Hmac};
use crate::decrypt::DecryptError;
use crate::header::{Header, HeaderError};

const PRELUDE: &[u8; 4] = b"CDOC";
const VERSION: u8 = 2;
const MAX_HEADER_LEN: usize = 1 << 20;
const HMAC_LEN: usize = 32;
const HHK_LEN: usize = 32;

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

impl Container<'_> {
    pub fn verify_header_hmac(&self, fmk: &[u8; FMK_LEN]) -> Result<(), DecryptError> {
        let hhk = derive_hhk(fmk);
        let mut mac = Hmac::new_from_slice(&hhk).expect("HMAC should accept keys of any size");
        mac.update(self.header_bytes);
        mac.verify_slice(self.header_hmac)
            .map_err(|_| DecryptError::HmacMismatch)
    }
}

fn derive_hhk(fmk: &[u8; FMK_LEN]) -> [u8; HHK_LEN] {
    let mut hhk = [0u8; HHK_LEN];
    let hk = Hkdf::from_prk(fmk).expect("FMK should be long enough to be an HKDF PRK");
    hk.expand(b"CDOC20hmac", &mut hhk)
        .expect("HHK should be short enough for HKDF-Expand");
    hhk
}
