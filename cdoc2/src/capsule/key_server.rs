//! Key server recipients.

use crate::capsule::ecc::EccPublicKeyCapsule;
use crate::capsule::{Capsule, EncryptedFmk, encrypt_fmk};
use crate::crypto::FMK_LEN;
use crate::header::RecipientRecord;
use crate::key_label;
use crate::keys::{EcPublicKey, EllipticCurve};

/// The capsule of a key server recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyServerCapsule {
    pub curve: EllipticCurve,
    /// The recipient's public key, as an uncompressed SEC1 point.
    pub recipient_public_key: Vec<u8>,
    pub keyserver_id: String,
    /// The capsule's ID on the key server.
    pub transaction_id: String,
}

impl KeyServerCapsule {
    /// Turns the capsule into an EC capsule, with the sender's public key fetched from the key
    /// server.
    ///
    /// If the server returns a wrong key, decryption fails.
    ///
    /// # Examples
    ///
    /// Decrypt for a key server recipient with an ID card, where `fetch` requests the sender's
    /// public key from the key server.
    ///
    /// ```no_run
    /// use cdoc2::capsule::Capsule;
    /// use cdoc2::decrypt::{DecryptOptions, DecryptionKey, decrypt};
    /// # use cdoc2::container::Container;
    /// # use cdoc2::header::RecipientRecord;
    /// # use cdoc2::keys::EcdhKey;
    /// # fn fetch(keyserver_id: &str, transaction_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    /// #     unimplemented!()
    /// # }
    /// # fn example(
    /// #     container: &Container,
    /// #     record: &RecipientRecord,
    /// #     card: &dyn EcdhKey,
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let Capsule::KeyServer(capsule) = &record.capsule else {
    ///     return Err("not a key server recipient".into());
    /// };
    /// let sender_public_key = fetch(&capsule.keyserver_id, &capsule.transaction_id)?;
    /// let mut fetched = record.clone();
    /// fetched.capsule = Capsule::Ecc(capsule.with_sender_public_key(sender_public_key));
    ///
    /// let key = DecryptionKey::Ecdh(card);
    /// let options = DecryptOptions::new(1 << 30); // 1 GiB
    /// let files = decrypt(container, &fetched, key, options)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sender_public_key(&self, sender_public_key: Vec<u8>) -> EccPublicKeyCapsule {
        EccPublicKeyCapsule {
            curve: self.curve,
            recipient_public_key: self.recipient_public_key.clone(),
            sender_public_key,
        }
    }
}

/// A key server capsule to be uploaded.
///
/// [`PreparedEncryption::capsule_uploads`](crate::encrypt::PreparedEncryption::capsule_uploads)
/// returns one for each key server recipient. Upload the recipient's and the sender's public
/// keys, then record the server's response with
/// [`set_transaction_id`](CapsuleUpload::set_transaction_id) and
/// [`set_expiry`](CapsuleUpload::set_expiry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleUpload {
    key_label: String,
    encrypted_fmk: EncryptedFmk,
    capsule: KeyServerCapsule,
    sender_public_key: Vec<u8>,
    not_after: Option<u64>,
    expiry: Option<u64>,
    expiry_adjusted: bool,
}

impl CapsuleUpload {
    pub(crate) fn generate(
        public_key: &EcPublicKey,
        key_label: &str,
        keyserver_id: &str,
        not_after: Option<u64>,
        fmk: &[u8; FMK_LEN],
    ) -> Result<Self, getrandom::Error> {
        let (ecc, kek) = EccPublicKeyCapsule::generate(public_key)?;
        Ok(CapsuleUpload {
            key_label: key_label.to_owned(),
            encrypted_fmk: encrypt_fmk(fmk, &kek),
            capsule: KeyServerCapsule {
                curve: ecc.curve,
                recipient_public_key: ecc.recipient_public_key,
                keyserver_id: keyserver_id.to_owned(),
                transaction_id: String::new(),
            },
            sender_public_key: ecc.sender_public_key,
            not_after,
            expiry: None,
            expiry_adjusted: false,
        })
    }

    pub(crate) fn key_label(&self) -> &str {
        &self.key_label
    }

    /// Returns the ID of the key server to upload to.
    pub fn keyserver_id(&self) -> &str {
        &self.capsule.keyserver_id
    }

    /// Returns the curve of the recipient's key.
    pub fn curve(&self) -> EllipticCurve {
        self.capsule.curve
    }

    /// Returns the recipient's public key, as an uncompressed SEC1 point.
    pub fn recipient_public_key(&self) -> &[u8] {
        &self.capsule.recipient_public_key
    }

    /// Returns the sender's public key, as an uncompressed SEC1 point.
    pub fn sender_public_key(&self) -> &[u8] {
        &self.sender_public_key
    }

    /// Returns when the recipient's certificate expires, in seconds since the Unix epoch, if
    /// [`Recipient::KeyServer`](crate::encrypt::Recipient::KeyServer) gave it.
    /// Request an expiry no later than this.
    pub fn not_after(&self) -> Option<u64> {
        self.not_after
    }

    /// Returns when the key server deletes the capsule, as recorded by
    /// [`set_expiry`](CapsuleUpload::set_expiry).
    pub fn expiry(&self) -> Option<u64> {
        self.expiry
    }

    /// Returns whether the key server changed the requested expiry.
    pub fn expiry_adjusted(&self) -> bool {
        self.expiry_adjusted
    }

    /// Records the capsule's ID on the key server.
    /// The container can't be written until it is set.
    pub fn set_transaction_id(&mut self, transaction_id: String) {
        self.capsule.transaction_id = transaction_id;
    }

    /// Records when the key server deletes the capsule, in seconds since the Unix epoch, and
    /// whether the server changed the requested time.
    ///
    /// The expiry is also added to the key label, as `server_exp`.
    pub fn set_expiry(&mut self, expiry: u64, adjusted: bool) {
        self.key_label = key_label::with_server_exp(&self.key_label, expiry);
        self.expiry = Some(expiry);
        self.expiry_adjusted = adjusted;
    }

    pub(crate) fn is_uploaded(&self) -> bool {
        !self.capsule.transaction_id.is_empty()
    }

    pub(crate) fn into_record(self) -> RecipientRecord {
        RecipientRecord::new(
            Capsule::KeyServer(self.capsule),
            self.key_label,
            self.encrypted_fmk,
        )
    }
}
