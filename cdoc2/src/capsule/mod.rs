//! Key capsules.

pub mod ecc;
pub mod key_server;
pub mod password;
pub mod symmetric;

use ecc::EccPublicKeyCapsule;
use key_server::KeyServerCapsule;
use password::Pbkdf2Capsule;
use symmetric::SymmetricKeyCapsule;

use crate::crypto::{FMK_LEN, Fmk, Hkdf, KEK_LEN, Kek};

const ALG_ID: &str = "XOR";
pub(crate) const SALT_LEN: usize = 32;

/// A recipient's capsule, by the kind of key the recipient has.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capsule {
    /// A symmetric key.
    Symmetric(SymmetricKeyCapsule),
    /// A password.
    Password(Pbkdf2Capsule),
    /// An EC private key.
    Ecc(EccPublicKeyCapsule),
    /// An EC private key, with the sender's public key kept on a key server.
    KeyServer(KeyServerCapsule),
    /// A kind of recipient that this crate can't decrypt for.
    Unsupported(UnsupportedCapsule),
}

/// A capsule that this crate can read but not decrypt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedCapsule {
    /// An RSA recipient.
    RsaPublicKey {
        /// The recipient's public key, as DER-encoded PKCS#1.
        recipient_public_key: Vec<u8>,
    },
    /// An RSA recipient, with the encrypted key material kept on a key server.
    RsaKeyServer {
        /// The recipient's public key, as DER-encoded PKCS#1.
        recipient_public_key: Vec<u8>,
        keyserver_id: String,
        /// The capsule's ID on the key server.
        transaction_id: String,
    },
    /// Smart-ID or Mobile-ID, with the key split into shares on several servers.
    KeyShares { recipient_id: String },
    /// A capsule type that this crate doesn't recognize.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EncryptedFmk([u8; FMK_LEN]);

impl EncryptedFmk {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn encrypt_fmk(fmk: &[u8; FMK_LEN], kek: &[u8; KEK_LEN]) -> EncryptedFmk {
    EncryptedFmk(xor(fmk, kek))
}

pub(crate) fn decrypt_fmk(encrypted_fmk: &[u8; FMK_LEN], kek: &[u8; KEK_LEN]) -> Fmk {
    let mut fmk = Fmk::default();
    **fmk = xor(encrypted_fmk, kek);
    fmk
}

pub(crate) fn expand_kek(hk: &Hkdf, context: &[&[u8]]) -> Kek {
    let info = [&[b"CDOC20kek", ALG_ID.as_bytes()], context].concat();
    let mut kek = Kek::default();
    hk.expand_multi_info(&info, &mut kek[..])
        .expect("KEK_LEN is a valid HKDF-Expand output length");
    kek
}

pub(crate) fn derive_symmetric_kek(salt: &[u8], key: &[u8], key_label: &str) -> Kek {
    let hk = Hkdf::new(Some(salt), key);
    expand_kek(&hk, &[key_label.as_bytes()])
}

fn xor(a: &[u8; FMK_LEN], b: &[u8; FMK_LEN]) -> [u8; FMK_LEN] {
    std::array::from_fn(|i| a[i] ^ b[i])
}
