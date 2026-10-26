use hmac::digest::MacError;
use hmac::{KeyInit, Mac};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const FMK_LEN: usize = 32;
pub(crate) const KEK_LEN: usize = FMK_LEN;
pub(crate) const HMAC_LEN: usize = 32;

pub(crate) type HashAlgorithm = sha2::Sha256;
pub(crate) type Hkdf = hkdf::Hkdf<HashAlgorithm>;
pub(crate) type Hmac = hmac::Hmac<HashAlgorithm>;

// We must box the KEK so that the instance is not duplicated, and it gets wiped on drop.
pub(crate) type Kek = Box<Zeroizing<[u8; KEK_LEN]>>;

// Fails to build if Cargo.toml loses necessary zeroize features.
// Inspired by RustCrypto.
// https://github.com/RustCrypto/traits/blob/8fffd5b1e6c5b9272b18efa967c55a8bd78d0d9b/cipher/src/stream/wrapper.rs#L223
const _: () = {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = wiped_on_drop::<chacha20::ChaCha20>;
    let _ = wiped_on_drop::<HashAlgorithm>;
};

const FMK_INPUT_LEN: usize = 32;
const WIPED_STACK_LEN: usize = 16 * 1024;
const HHK_LEN: usize = 32;
const CEK_LEN: usize = 32;

#[inline(never)]
pub(crate) fn wipe_stack() {
    let mut area = [0u8; WIPED_STACK_LEN];
    area.zeroize();
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

// We box it so that moving the FMK only copies a pointer, and we can
// zeroize the only FMK copy on drop.
pub(crate) fn generate_fmk() -> Result<Box<Zeroizing<[u8; FMK_LEN]>>, getrandom::Error> {
    let ikm = random_bytes::<FMK_INPUT_LEN>()?;
    let (prk, _) = Hkdf::extract(Some(b"CDOC20salt"), &ikm);
    let mut fmk = Box::new(Zeroizing::new([0u8; FMK_LEN]));
    fmk.copy_from_slice(&prk);
    Ok(fmk)
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
    fmk: Zeroizing<[u8; FMK_LEN]>,
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
    fmk: Zeroizing<[u8; FMK_LEN]>,
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
