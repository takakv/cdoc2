use hmac::digest::MacError;
use hmac::{KeyInit, Mac};

pub const FMK_LEN: usize = 32;
pub(crate) const HMAC_LEN: usize = 32;

pub(crate) type HashAlgorithm = sha2::Sha256;
pub(crate) type Hkdf = hkdf::Hkdf<HashAlgorithm>;
pub(crate) type Hmac = hmac::Hmac<HashAlgorithm>;

const FMK_INPUT_LEN: usize = 32;
const HHK_LEN: usize = 32;
const CEK_LEN: usize = 32;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn generate_fmk() -> Result<[u8; FMK_LEN], getrandom::Error> {
    let ikm = random_bytes::<FMK_INPUT_LEN>()?;
    let (fmk, _) = Hkdf::extract(Some(b"CDOC20salt"), &ikm);
    Ok(fmk.into())
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

pub(crate) struct AuthenticatedHeader<'a> {
    fmk: [u8; FMK_LEN],
    header_bytes: &'a [u8],
    header_hmac: &'a [u8; HMAC_LEN],
}

impl<'a> AuthenticatedHeader<'a> {
    pub(crate) fn fmk(&self) -> &[u8; FMK_LEN] {
        &self.fmk
    }

    pub(crate) fn header_bytes(&self) -> &'a [u8] {
        self.header_bytes
    }

    pub(crate) fn header_hmac(&self) -> &'a [u8; HMAC_LEN] {
        self.header_hmac
    }
}

pub(crate) fn authenticate_header<'a>(
    fmk: [u8; FMK_LEN],
    header_bytes: &'a [u8],
    header_hmac: &'a [u8; HMAC_LEN],
) -> Result<AuthenticatedHeader<'a>, MacError> {
    header_mac(&fmk, header_bytes).verify_slice(header_hmac)?;
    Ok(AuthenticatedHeader {
        fmk,
        header_bytes,
        header_hmac,
    })
}

fn derive_hhk(fmk: &[u8; FMK_LEN]) -> [u8; HHK_LEN] {
    expand_fmk(fmk, b"CDOC20hmac")
}

pub(crate) fn derive_cek(fmk: &[u8; FMK_LEN]) -> [u8; CEK_LEN] {
    expand_fmk(fmk, b"CDOC20cek")
}

fn expand_fmk<const N: usize>(fmk: &[u8; FMK_LEN], info: &[u8]) -> [u8; N] {
    let mut key = [0u8; N];
    let hk = Hkdf::from_prk(fmk).expect("FMK should be long enough to be an HKDF PRK");
    hk.expand(info, &mut key)
        .expect("key should be short enough for HKDF-Expand");
    key
}
