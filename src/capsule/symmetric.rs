use hkdf::Hkdf;
use sha2::Sha256;

const ALG_ID: &str = "XOR";
const FMK_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKeyCapsule {
    pub salt: Vec<u8>,
}

impl SymmetricKeyCapsule {
    pub fn derive_kek(&self, key: &[u8], key_label: &str) -> [u8; FMK_LEN] {
        let hk = Hkdf::<Sha256>::new(Some(&self.salt), key);
        let mut kek = [0u8; FMK_LEN];
        hk.expand_multi_info(
            &[b"CDOC20kek", ALG_ID.as_bytes(), key_label.as_bytes()],
            &mut kek,
        )
        .expect("32 is a valid length for Sha256 to output");
        kek
    }
}
