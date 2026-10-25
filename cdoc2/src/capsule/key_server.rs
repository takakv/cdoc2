use crate::capsule::ecc::{EcPublicKey, EccPublicKeyCapsule, EllipticCurve};
use crate::capsule::{Capsule, encrypt_fmk};
use crate::crypto::FMK_LEN;
use crate::header::{FmkEncryptionMethod, RecipientRecord};
use crate::key_label;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyServerCapsule {
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub keyserver_id: String,
    pub transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleUpload {
    key_label: String,
    encrypted_fmk: Vec<u8>,
    capsule: KeyServerCapsule,
    sender_public_key: Vec<u8>,
}

impl CapsuleUpload {
    pub(crate) fn generate(
        public_key: &EcPublicKey,
        key_label: &str,
        keyserver_id: &str,
        fmk: &[u8; FMK_LEN],
    ) -> Result<Self, getrandom::Error> {
        let (ecc, kek) = EccPublicKeyCapsule::generate(public_key)?;
        Ok(CapsuleUpload {
            key_label: key_label.to_owned(),
            encrypted_fmk: encrypt_fmk(fmk, &kek).to_vec(),
            capsule: KeyServerCapsule {
                curve: ecc.curve,
                recipient_public_key: ecc.recipient_public_key,
                keyserver_id: keyserver_id.to_owned(),
                transaction_id: String::new(),
            },
            sender_public_key: ecc.sender_public_key,
        })
    }

    pub fn key_label(&self) -> &str {
        &self.key_label
    }

    pub fn keyserver_id(&self) -> &str {
        &self.capsule.keyserver_id
    }

    pub fn curve(&self) -> EllipticCurve {
        self.capsule.curve
    }

    pub fn recipient_public_key(&self) -> &[u8] {
        &self.capsule.recipient_public_key
    }

    pub fn sender_public_key(&self) -> &[u8] {
        &self.sender_public_key
    }

    pub fn set_transaction_id(&mut self, transaction_id: String) {
        self.capsule.transaction_id = transaction_id;
    }

    pub fn set_expiry(&mut self, expiry: u64) {
        self.key_label = key_label::with_server_exp(&self.key_label, expiry);
    }

    pub(crate) fn is_uploaded(&self) -> bool {
        !self.capsule.transaction_id.is_empty()
    }

    pub(crate) fn into_record(self) -> RecipientRecord {
        RecipientRecord {
            capsule: Capsule::KeyServer(self.capsule),
            key_label: self.key_label,
            encrypted_fmk: self.encrypted_fmk,
            fmk_encryption_method: FmkEncryptionMethod::Xor,
        }
    }
}
