use crate::capsule::ecc::{EcPublicKey, EccPublicKeyCapsule, EllipticCurve};
use crate::capsule::{Capsule, record_with_kek};
use crate::crypto::FMK_LEN;
use crate::header::RecipientRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyServerCapsule {
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub keyserver_id: String,
    pub transaction_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleUpload {
    pub keyserver_id: String,
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub sender_public_key: Vec<u8>,
    pub transaction_id: Option<String>,
}

pub(crate) fn recipient_record(
    public_key: &EcPublicKey,
    key_label: &str,
    keyserver_id: &str,
    fmk: &[u8; FMK_LEN],
) -> Result<(RecipientRecord, CapsuleUpload), getrandom::Error> {
    let (ecc, kek) = EccPublicKeyCapsule::generate(public_key)?;
    let capsule = KeyServerCapsule {
        curve: ecc.curve,
        recipient_public_key: ecc.recipient_public_key.clone(),
        keyserver_id: keyserver_id.to_owned(),
        transaction_id: String::new(),
    };
    let upload = CapsuleUpload {
        keyserver_id: keyserver_id.to_owned(),
        curve: ecc.curve,
        recipient_public_key: ecc.recipient_public_key,
        sender_public_key: ecc.sender_public_key,
        transaction_id: None,
    };
    let record = record_with_kek(Capsule::KeyServer(capsule), key_label, &kek, fmk);
    Ok((record, upload))
}
