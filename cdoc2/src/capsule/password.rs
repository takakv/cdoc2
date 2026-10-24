use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

use crate::capsule::symmetric::{SALT_LEN, derive_symmetric_kek};
use crate::capsule::{Capsule, record_with_kek};
use crate::crypto::{FMK_LEN, random_bytes};
use crate::header::RecipientRecord;

pub(crate) const KDF_ITERATIONS: u32 = 600_000;
const PASSWORD_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbkdf2Capsule {
    pub salt: Vec<u8>,
    pub password_salt: Vec<u8>,
    pub kdf_iterations: u32,
}

impl Pbkdf2Capsule {
    pub(crate) fn generate() -> Result<Self, getrandom::Error> {
        Ok(Pbkdf2Capsule {
            salt: random_bytes::<SALT_LEN>()?.to_vec(),
            password_salt: random_bytes::<SALT_LEN>()?.to_vec(),
            kdf_iterations: KDF_ITERATIONS,
        })
    }

    pub fn derive_kek(&self, password: &str, key_label: &str) -> [u8; FMK_LEN] {
        let ikm = pbkdf2_hmac_array::<Sha256, PASSWORD_KEY_LEN>(
            password.as_bytes(),
            &self.password_salt,
            self.kdf_iterations,
        );
        derive_symmetric_kek(&self.salt, &ikm, key_label)
    }
}

pub(crate) fn recipient_record(
    password: &str,
    key_label: &str,
    fmk: &[u8; FMK_LEN],
) -> Result<RecipientRecord, getrandom::Error> {
    let capsule = Pbkdf2Capsule::generate()?;
    let kek = capsule.derive_kek(password, key_label);
    Ok(record_with_kek(
        Capsule::Password(capsule),
        key_label,
        &kek,
        fmk,
    ))
}
