use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;

use crate::capsule::symmetric::derive_symmetric_kek;
use crate::crypto::FMK_LEN;

pub(crate) const KDF_ITERATIONS: u32 = 600_000;
const PASSWORD_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbkdf2Capsule {
    pub salt: Vec<u8>,
    pub password_salt: Vec<u8>,
    pub kdf_iterations: u32,
}

impl Pbkdf2Capsule {
    pub fn derive_kek(&self, password: &str, key_label: &str) -> [u8; FMK_LEN] {
        let ikm = pbkdf2_hmac_array::<Sha256, PASSWORD_KEY_LEN>(
            password.as_bytes(),
            &self.password_salt,
            self.kdf_iterations,
        );
        derive_symmetric_kek(&self.salt, &ikm, key_label)
    }
}
