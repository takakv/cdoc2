pub mod password;
pub mod symmetric;

use password::Pbkdf2Capsule;
use symmetric::SymmetricKeyCapsule;

use crate::crypto::FMK_LEN;
use crate::decrypt::DecryptError;
use crate::header::{FmkEncryptionMethod, RecipientRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    Symmetric(SymmetricKeyCapsule),
    Password(Pbkdf2Capsule),
    Unsupported,
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
