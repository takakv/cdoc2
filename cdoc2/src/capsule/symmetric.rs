use crate::crypto::{FMK_LEN, Hkdf, random_bytes};
use crate::decrypt::DecryptError;
use crate::header::{FmkEncryptionMethod, RecipientRecord};

use super::Capsule;

const ALG_ID: &str = "XOR";
const SALT_LEN: usize = 32;

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
    let mut kek = [0u8; FMK_LEN];
    hk.expand_multi_info(
        &[b"CDOC20kek", ALG_ID.as_bytes(), key_label.as_bytes()],
        &mut kek,
    )
    .expect("32 is a valid length for Sha256 to output");
    kek
}

fn xor(a: &[u8; FMK_LEN], b: &[u8; FMK_LEN]) -> [u8; FMK_LEN] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

pub fn encrypt_fmk(fmk: &[u8; FMK_LEN], kek: &[u8; FMK_LEN]) -> [u8; FMK_LEN] {
    xor(fmk, kek)
}

pub fn decrypt_fmk(
    encrypted_fmk: &[u8],
    kek: &[u8; FMK_LEN],
) -> Result<[u8; FMK_LEN], DecryptError> {
    let encrypted_fmk: &[u8; FMK_LEN] = encrypted_fmk
        .try_into()
        .map_err(|_| DecryptError::InvalidEncryptedFmkLength(encrypted_fmk.len()))?;
    Ok(xor(encrypted_fmk, kek))
}

pub(crate) fn recipient_record(
    key: &[u8],
    key_label: &str,
    fmk: &[u8; FMK_LEN],
) -> Result<RecipientRecord, getrandom::Error> {
    let capsule = SymmetricKeyCapsule::generate()?;
    let kek = capsule.derive_kek(key, key_label);
    let encrypted_fmk = encrypt_fmk(fmk, &kek);

    Ok(RecipientRecord {
        capsule: Capsule::Symmetric(capsule),
        key_label: key_label.to_owned(),
        encrypted_fmk: encrypted_fmk.to_vec(),
        fmk_encryption_method: FmkEncryptionMethod::Xor,
    })
}
