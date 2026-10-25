use p256::pkcs8::DecodePublicKey;
use sha1::{Digest, Sha1};
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::oid::db::rfc4519;
use x509_cert::der::{Any, Decode, Encode, Tag, Tagged};
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::ext::pkix::{CertificatePolicies, KeyUsage};

use crate::key_label::{self, CertLabel, EidLabel, EidType};
use crate::keys::EcPublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateKey {
    pub public_key: EcPublicKey,
    pub key_label: String,
    pub not_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificateError {
    #[error("not an X.509 certificate")]
    Invalid,
    #[error("the certificate has no P-256, P-384 or P-521 public key")]
    UnsupportedKey,
    #[error("the certificate's key usage does not allow key agreement")]
    NoKeyAgreement,
}

/// Reads the EC public key of a DER certificate, with an eID key label for Estonian eID
/// certificates and a `cert` key label naming `file_name` for others.
pub fn parse(der: &[u8], file_name: &str) -> Result<CertificateKey, CertificateError> {
    let cert = Certificate::from_der(der).map_err(|_| CertificateError::Invalid)?;
    let key_usage = cert
        .tbs_certificate()
        .get_extension::<KeyUsage>()
        .map_err(|_| CertificateError::Invalid)?;
    if let Some((_, key_usage)) = key_usage
        && !key_usage.key_agreement()
    {
        return Err(CertificateError::NoKeyAgreement);
    }
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| CertificateError::Invalid)?;
    let public_key = public_key(&spki).ok_or(CertificateError::UnsupportedKey)?;
    let not_after = cert.tbs_certificate().validity().not_after;
    Ok(CertificateKey {
        public_key,
        key_label: key_label(&cert, der, file_name),
        not_after: not_after.to_unix_duration().as_secs(),
    })
}

fn public_key(spki: &[u8]) -> Option<EcPublicKey> {
    if let Ok(key) = p256::PublicKey::from_public_key_der(spki) {
        return Some(EcPublicKey::P256(key));
    }
    if let Ok(key) = p384::PublicKey::from_public_key_der(spki) {
        return Some(EcPublicKey::P384(key));
    }
    p521::PublicKey::from_public_key_der(spki)
        .ok()
        .map(EcPublicKey::P521)
}

fn key_label(cert: &Certificate, der: &[u8], file_name: &str) -> String {
    let subject = cert.tbs_certificate().subject();
    let attribute = |oid: ObjectIdentifier| {
        let value = subject.by_oid::<DirectoryString>(oid).ok().flatten()?;
        Some(value.value().into_owned())
    };
    let cn = attribute(rfc4519::COMMON_NAME);
    if let Some(eid_type) = eid_type(cert)
        && let (Some(cn), Some(serial_number)) = (&cn, attribute(rfc4519::SERIAL_NUMBER))
    {
        return key_label::eid(&EidLabel {
            eid_type,
            cn,
            serial_number: &serial_number,
            first_name: attribute(rfc4519::GIVEN_NAME).as_deref(),
            last_name: attribute(rfc4519::SN).as_deref(),
        });
    }

    let sha1: String = Sha1::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    key_label::cert(&CertLabel {
        file: file_name,
        cn: cn.as_deref(),
        cert_sha1: Some(&sha1),
    })
}

const DIGI_ID: &[ObjectIdentifier] = &[
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.1.1.3"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.1.2.3"),
];
const DIGI_ID_E_RESIDENT: &[ObjectIdentifier] = &[
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.1.1.4"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.1.2.4"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.2.1.6"),
];
const ID_CARD: &[ObjectIdentifier] = &[
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.1.1"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.1.2"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51361.2.1"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51455.1.1"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51455.1.2"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.51455.2.1"),
];

fn eid_type(cert: &Certificate) -> Option<EidType> {
    policy_oids(cert).iter().find_map(|oid| {
        let under = |arcs: &[ObjectIdentifier]| arcs.iter().any(|arc| oid.starts_with(*arc));
        if under(DIGI_ID) {
            Some(EidType::DigiId)
        } else if under(DIGI_ID_E_RESIDENT) {
            Some(EidType::DigiIdEResident)
        } else if under(ID_CARD) {
            Some(EidType::IdCard)
        } else {
            None
        }
    })
}

// We must decode by hand because `ObjectIdentifier` rejects OIDs under 2.40 and above and
// `CertificatePolicies` thus fails on the 2.999 OIDs of test cards.
fn policy_oids(cert: &Certificate) -> Vec<ObjectIdentifier> {
    let extension = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|extension| extension.extn_id == CertificatePolicies::OID);
    let Some(policies) = extension
        .and_then(|extension| Vec::<Vec<Any>>::from_der(extension.extn_value.as_bytes()).ok())
    else {
        return Vec::new();
    };
    policies
        .iter()
        .filter_map(|policy| {
            let oid = policy
                .first()
                .filter(|oid| oid.tag() == Tag::ObjectIdentifier)?;
            policy_oid(oid.value())
        })
        .collect()
}

// Test card policies are the real cards' policies under 2.999. We thus replace the encoded
// 2.999.1.3 (88 37 01 03) by 1.3 (2b) to get the real card policies.
fn policy_oid(bytes: &[u8]) -> Option<ObjectIdentifier> {
    match bytes {
        [0x88, 0x37, 0x01, 0x03, rest @ ..] => {
            ObjectIdentifier::from_bytes(&[&[0x2b], rest].concat())
        }
        _ => ObjectIdentifier::from_bytes(bytes),
    }
    .ok()
}
