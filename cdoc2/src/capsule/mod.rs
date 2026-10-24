pub mod ecc;
pub mod password;
pub mod symmetric;

use ecc::EccPublicKeyCapsule;
use password::Pbkdf2Capsule;
use symmetric::SymmetricKeyCapsule;

use crate::crypto::{FMK_LEN, Hkdf};
use crate::header::{FmkEncryptionMethod, RecipientRecord};

const ALG_ID: &str = "XOR";
pub(crate) const SALT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    Symmetric(SymmetricKeyCapsule),
    Password(Pbkdf2Capsule),
    Ecc(EccPublicKeyCapsule),
    Unsupported,
}

pub fn encrypt_fmk(fmk: &[u8; FMK_LEN], kek: &[u8; FMK_LEN]) -> [u8; FMK_LEN] {
    xor(fmk, kek)
}

pub fn decrypt_fmk(encrypted_fmk: &[u8; FMK_LEN], kek: &[u8; FMK_LEN]) -> [u8; FMK_LEN] {
    xor(encrypted_fmk, kek)
}

pub(crate) fn expand_kek(hk: &Hkdf, context: &[&[u8]]) -> [u8; FMK_LEN] {
    let info = [&[b"CDOC20kek", ALG_ID.as_bytes()], context].concat();
    let mut kek = [0u8; FMK_LEN];
    hk.expand_multi_info(&info, &mut kek)
        .expect("FMK_LEN is a valid HKDF-Expand output length");
    kek
}

pub(crate) fn derive_symmetric_kek(salt: &[u8], key: &[u8], key_label: &str) -> [u8; FMK_LEN] {
    let hk = Hkdf::new(Some(salt), key);
    expand_kek(&hk, &[key_label.as_bytes()])
}

pub(crate) fn record_with_kek(
    capsule: Capsule,
    key_label: &str,
    kek: &[u8; FMK_LEN],
    fmk: &[u8; FMK_LEN],
) -> RecipientRecord {
    RecipientRecord {
        capsule,
        key_label: key_label.to_owned(),
        encrypted_fmk: encrypt_fmk(fmk, kek).to_vec(),
        fmk_encryption_method: FmkEncryptionMethod::Xor,
    }
}

fn xor(a: &[u8; FMK_LEN], b: &[u8; FMK_LEN]) -> [u8; FMK_LEN] {
    std::array::from_fn(|i| a[i] ^ b[i])
}
