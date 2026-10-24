use crate::capsule::{Capsule, expand_kek, record_with_kek};
use crate::crypto::{FMK_LEN, Hkdf, random_bytes};
use crate::header::RecipientRecord;

pub(crate) const SALT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKeyCapsule {
    pub salt: Vec<u8>,
}

impl SymmetricKeyCapsule {
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        Ok(SymmetricKeyCapsule {
            salt: random_bytes::<SALT_LEN>()?.to_vec(),
        })
    }

    pub fn derive_kek(&self, key: &[u8], key_label: &str) -> [u8; FMK_LEN] {
        derive_symmetric_kek(&self.salt, key, key_label)
    }
}

pub(crate) fn derive_symmetric_kek(salt: &[u8], key: &[u8], key_label: &str) -> [u8; FMK_LEN] {
    let hk = Hkdf::new(Some(salt), key);
    expand_kek(&hk, &[key_label.as_bytes()])
}

pub(crate) fn recipient_record(
    key: &[u8],
    key_label: &str,
    fmk: &[u8; FMK_LEN],
) -> Result<RecipientRecord, getrandom::Error> {
    let capsule = SymmetricKeyCapsule::generate()?;
    let kek = capsule.derive_kek(key, key_label);
    Ok(record_with_kek(
        Capsule::Symmetric(capsule),
        key_label,
        &kek,
        fmk,
    ))
}
