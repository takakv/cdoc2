use crate::crypto::{FMK_LEN, Hkdf};
use crate::decrypt::DecryptError;

const ALG_ID: &str = "XOR";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKeyCapsule {
    pub salt: Vec<u8>,
}

impl SymmetricKeyCapsule {
    pub fn derive_kek(&self, key: &[u8], key_label: &str) -> [u8; FMK_LEN] {
        let hk = Hkdf::new(Some(&self.salt), key);
        let mut kek = [0u8; FMK_LEN];
        hk.expand_multi_info(
            &[b"CDOC20kek", ALG_ID.as_bytes(), key_label.as_bytes()],
            &mut kek,
        )
        .expect("32 is a valid length for Sha256 to output");
        kek
    }
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
