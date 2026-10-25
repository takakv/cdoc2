use crate::capsule::{Capsule, SALT_LEN, derive_symmetric_kek, encrypt_fmk};
use crate::crypto::{FMK_LEN, random_bytes};
use crate::header::RecipientRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKeyCapsule {
    pub(crate) salt: Vec<u8>,
}

impl SymmetricKeyCapsule {
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        Ok(SymmetricKeyCapsule {
            salt: random_bytes::<SALT_LEN>()?.to_vec(),
        })
    }

    pub(crate) fn derive_kek(&self, key: &[u8], key_label: &str) -> [u8; FMK_LEN] {
        derive_symmetric_kek(&self.salt, key, key_label)
    }
}

pub(crate) fn recipient_record(
    key: &[u8],
    key_label: &str,
    fmk: &[u8; FMK_LEN],
) -> Result<RecipientRecord, getrandom::Error> {
    let capsule = SymmetricKeyCapsule::generate()?;
    let kek = capsule.derive_kek(key, key_label);
    Ok(RecipientRecord::new(
        Capsule::Symmetric(capsule),
        key_label,
        encrypt_fmk(fmk, &kek),
    ))
}
