use flatbuffers::{FlatBufferBuilder, WIPOffset};

use super::generated::ee::cyber::cdoc_2::fbs::header as fb;
use super::generated::ee::cyber::cdoc_2::fbs::recipients as fb_rec;
use super::{FmkEncryptionMethod, Header, HeaderError, PayloadEncryptionMethod, RecipientRecord};
use crate::capsule::Capsule;
use crate::capsule::ecc::{EccPublicKeyCapsule, EllipticCurve};
use crate::capsule::key_server::KeyServerCapsule;
use crate::capsule::password::Pbkdf2Capsule;
use crate::capsule::symmetric::SymmetricKeyCapsule;

pub(super) fn header_from_bytes(bytes: &[u8]) -> Result<Header, HeaderError> {
    let header = fb::root_as_header(bytes).map_err(|e| HeaderError::Malformed(e.to_string()))?;

    let payload_encryption_method = match header.payload_encryption_method() {
        fb::PayloadEncryptionMethod::CHACHA20POLY1305 => PayloadEncryptionMethod::ChaCha20Poly1305,
        _ => PayloadEncryptionMethod::Unknown,
    };

    let recipients = header
        .recipients()
        .filter(|records| !records.is_empty())
        .ok_or_else(|| HeaderError::Malformed("no recipients".into()))?
        .iter()
        .map(record_from_fb)
        .collect();

    Ok(Header {
        recipients,
        payload_encryption_method,
    })
}

pub(super) fn header_to_bytes(header: &Header) -> Vec<u8> {
    let payload_encryption_method = match header.payload_encryption_method {
        PayloadEncryptionMethod::ChaCha20Poly1305 => fb::PayloadEncryptionMethod::CHACHA20POLY1305,
        PayloadEncryptionMethod::Unknown => panic!("cannot write an unknown payload method"),
    };

    let mut fbb = FlatBufferBuilder::new();
    let records: Vec<WIPOffset<fb::RecipientRecord>> = header
        .recipients
        .iter()
        .map(|record| record_to_fb(&mut fbb, record))
        .collect();
    let recipients = fbb.create_vector(&records);

    let header = fb::Header::create(
        &mut fbb,
        &fb::HeaderArgs {
            recipients: Some(recipients),
            payload_encryption_method,
        },
    );
    fbb.finish(header, None);
    fbb.finished_data().to_vec()
}

fn record_from_fb(record: fb::RecipientRecord<'_>) -> RecipientRecord {
    let fmk_encryption_method = match record.fmk_encryption_method() {
        fb::FMKEncryptionMethod::XOR => FmkEncryptionMethod::Xor,
        _ => FmkEncryptionMethod::Unknown,
    };

    RecipientRecord {
        capsule: capsule_from_fb(record).unwrap_or(Capsule::Unsupported),
        key_label: record.key_label().to_owned(),
        encrypted_fmk: record.encrypted_fmk().bytes().to_vec(),
        fmk_encryption_method,
    }
}

fn record_to_fb<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    record: &RecipientRecord,
) -> WIPOffset<fb::RecipientRecord<'a>> {
    let (capsule_type, capsule) = match &record.capsule {
        Capsule::Symmetric(c) => (
            fb::Capsule::recipients_SymmetricKeyCapsule,
            symmetric_capsule_to_fb(fbb, c).as_union_value(),
        ),
        Capsule::Password(c) => (
            fb::Capsule::recipients_PBKDF2Capsule,
            password_capsule_to_fb(fbb, c).as_union_value(),
        ),
        Capsule::Ecc(c) => (
            fb::Capsule::recipients_ECCPublicKeyCapsule,
            ecc_capsule_to_fb(fbb, c).as_union_value(),
        ),
        Capsule::KeyServer(c) => (
            fb::Capsule::recipients_KeyServerCapsule,
            key_server_capsule_to_fb(fbb, c).as_union_value(),
        ),
        Capsule::Unsupported => panic!("cannot write an unsupported capsule"),
    };

    let fmk_encryption_method = match record.fmk_encryption_method {
        FmkEncryptionMethod::Xor => fb::FMKEncryptionMethod::XOR,
        FmkEncryptionMethod::Unknown => panic!("cannot write an unknown FMK method"),
    };

    let key_label = fbb.create_string(&record.key_label);
    let encrypted_fmk = fbb.create_vector(&record.encrypted_fmk);
    fb::RecipientRecord::create(
        fbb,
        &fb::RecipientRecordArgs {
            capsule_type,
            capsule: Some(capsule),
            key_label: Some(key_label),
            encrypted_fmk: Some(encrypted_fmk),
            fmk_encryption_method,
        },
    )
}

fn capsule_from_fb(record: fb::RecipientRecord<'_>) -> Option<Capsule> {
    if let Some(c) = record.capsule_as_recipients_symmetric_key_capsule() {
        Some(Capsule::Symmetric(symmetric_capsule_from_fb(c)))
    } else if let Some(c) = record.capsule_as_recipients_pbkdf2_capsule() {
        password_capsule_from_fb(c).map(Capsule::Password)
    } else if let Some(c) = record.capsule_as_recipients_eccpublic_key_capsule() {
        ecc_capsule_from_fb(c).map(Capsule::Ecc)
    } else if let Some(c) = record.capsule_as_recipients_key_server_capsule() {
        key_server_capsule_from_fb(c).map(Capsule::KeyServer)
    } else {
        None
    }
}

fn symmetric_capsule_from_fb(capsule: fb_rec::SymmetricKeyCapsule<'_>) -> SymmetricKeyCapsule {
    SymmetricKeyCapsule {
        salt: capsule.salt().bytes().to_vec(),
    }
}

fn symmetric_capsule_to_fb<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    capsule: &SymmetricKeyCapsule,
) -> WIPOffset<fb_rec::SymmetricKeyCapsule<'a>> {
    let salt = fbb.create_vector(&capsule.salt);
    fb_rec::SymmetricKeyCapsule::create(fbb, &fb_rec::SymmetricKeyCapsuleArgs { salt: Some(salt) })
}

fn password_capsule_from_fb(capsule: fb_rec::PBKDF2Capsule<'_>) -> Option<Pbkdf2Capsule> {
    if capsule.kdf_algorithm_identifier() != fb_rec::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256 {
        return None;
    }
    let kdf_iterations = u32::try_from(capsule.kdf_iterations())
        .ok()
        .filter(|&n| n > 0)?;

    Some(Pbkdf2Capsule {
        salt: capsule.salt().bytes().to_vec(),
        password_salt: capsule.password_salt().bytes().to_vec(),
        kdf_iterations,
    })
}

fn password_capsule_to_fb<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    capsule: &Pbkdf2Capsule,
) -> WIPOffset<fb_rec::PBKDF2Capsule<'a>> {
    let kdf_iterations = i32::try_from(capsule.kdf_iterations)
        .expect("the iteration count fits in the header's i32");

    let salt = fbb.create_vector(&capsule.salt);
    let password_salt = fbb.create_vector(&capsule.password_salt);
    fb_rec::PBKDF2Capsule::create(
        fbb,
        &fb_rec::PBKDF2CapsuleArgs {
            salt: Some(salt),
            password_salt: Some(password_salt),
            kdf_algorithm_identifier: fb_rec::KDFAlgorithmIdentifier::PBKDF2WithHmacSHA256,
            kdf_iterations,
        },
    )
}

fn ecc_capsule_from_fb(capsule: fb_rec::ECCPublicKeyCapsule<'_>) -> Option<EccPublicKeyCapsule> {
    Some(EccPublicKeyCapsule {
        curve: curve_from_fb(capsule.curve())?,
        recipient_public_key: capsule.recipient_public_key().bytes().to_vec(),
        sender_public_key: capsule.sender_public_key().bytes().to_vec(),
    })
}

fn ecc_capsule_to_fb<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    capsule: &EccPublicKeyCapsule,
) -> WIPOffset<fb_rec::ECCPublicKeyCapsule<'a>> {
    let recipient_public_key = fbb.create_vector(&capsule.recipient_public_key);
    let sender_public_key = fbb.create_vector(&capsule.sender_public_key);
    fb_rec::ECCPublicKeyCapsule::create(
        fbb,
        &fb_rec::ECCPublicKeyCapsuleArgs {
            curve: curve_to_fb(capsule.curve),
            recipient_public_key: Some(recipient_public_key),
            sender_public_key: Some(sender_public_key),
        },
    )
}

fn key_server_capsule_from_fb(capsule: fb_rec::KeyServerCapsule<'_>) -> Option<KeyServerCapsule> {
    let details = capsule.recipient_key_details_as_ecc_key_details()?;
    Some(KeyServerCapsule {
        curve: curve_from_fb(details.curve())?,
        recipient_public_key: details.recipient_public_key().bytes().to_vec(),
        keyserver_id: capsule.keyserver_id().to_owned(),
        transaction_id: capsule.transaction_id().to_owned(),
    })
}

fn key_server_capsule_to_fb<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    capsule: &KeyServerCapsule,
) -> WIPOffset<fb_rec::KeyServerCapsule<'a>> {
    let recipient_public_key = fbb.create_vector(&capsule.recipient_public_key);
    let details = fb_rec::EccKeyDetails::create(
        fbb,
        &fb_rec::EccKeyDetailsArgs {
            curve: curve_to_fb(capsule.curve),
            recipient_public_key: Some(recipient_public_key),
        },
    );
    let keyserver_id = fbb.create_string(&capsule.keyserver_id);
    let transaction_id = fbb.create_string(&capsule.transaction_id);
    fb_rec::KeyServerCapsule::create(
        fbb,
        &fb_rec::KeyServerCapsuleArgs {
            recipient_key_details_type: fb_rec::KeyDetailsUnion::EccKeyDetails,
            recipient_key_details: Some(details.as_union_value()),
            keyserver_id: Some(keyserver_id),
            transaction_id: Some(transaction_id),
        },
    )
}

fn curve_from_fb(curve: fb_rec::EllipticCurve) -> Option<EllipticCurve> {
    match curve {
        fb_rec::EllipticCurve::secp256r1 => Some(EllipticCurve::Secp256r1),
        fb_rec::EllipticCurve::secp384r1 => Some(EllipticCurve::Secp384r1),
        fb_rec::EllipticCurve::secp521r1 => Some(EllipticCurve::Secp521r1),
        _ => None,
    }
}

fn curve_to_fb(curve: EllipticCurve) -> fb_rec::EllipticCurve {
    match curve {
        EllipticCurve::Secp256r1 => fb_rec::EllipticCurve::secp256r1,
        EllipticCurve::Secp384r1 => fb_rec::EllipticCurve::secp384r1,
        EllipticCurve::Secp521r1 => fb_rec::EllipticCurve::secp521r1,
    }
}
