//! Key labels.
//!
//! See [KeyLabel field specification] in the spec for the fields.
//!
//! [KeyLabel field specification]: https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/keylabel_field/

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// A parsed structured key label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLabel {
    fields: Vec<(String, String)>,
}

impl KeyLabel {
    /// Returns the value of the field `name`, ignoring ASCII case. If the field appears more
    /// than once, returns the first value.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Builds the label of a symmetric key recipient.
pub fn symmetric(label: &str) -> String {
    structured("secret", &[("label", label)])
}

/// Builds the label of a password recipient.
pub fn password(label: &str) -> String {
    structured("pw", &[("label", label)])
}

/// Builds the label of a recipient whose public key was read from `file`.
pub fn public_key(file: &str, label: Option<&str>) -> String {
    structured(
        "pub_key",
        &present([("file", Some(file)), ("label", label)]),
    )
}

/// A kind of Estonian eID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EidType {
    IdCard,
    DigiId,
    DigiIdEResident,
}

impl EidType {
    fn as_str(self) -> &'static str {
        match self {
            EidType::IdCard => "ID-card",
            EidType::DigiId => "Digi-ID",
            EidType::DigiIdEResident => "Digi-ID E-RESIDENT",
        }
    }
}

/// The fields of an eID recipient's label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EidLabel<'a> {
    pub eid_type: EidType,
    /// The certificate subject's common name.
    pub cn: &'a str,
    /// The certificate subject's serial number.
    pub serial_number: &'a str,
    pub first_name: Option<&'a str>,
    pub last_name: Option<&'a str>,
}

/// The fields of the label of a recipient whose certificate was read from a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertLabel<'a> {
    pub file: &'a str,
    /// The certificate subject's common name.
    pub cn: Option<&'a str>,
    /// The SHA-1 hash of the DER-encoded certificate, in lowercase hex.
    pub cert_sha1: Option<&'a str>,
}

/// Builds the label of an Estonian eID recipient.
pub fn eid(label: &EidLabel) -> String {
    structured(
        label.eid_type.as_str(),
        &present([
            ("serial_number", Some(label.serial_number)),
            ("cn", Some(label.cn)),
            ("first_name", label.first_name),
            ("last_name", label.last_name),
        ]),
    )
}

/// Builds the label of a recipient whose certificate was read from a file.
pub fn cert(label: &CertLabel) -> String {
    structured(
        "cert",
        &present([
            ("file", Some(label.file)),
            ("cn", label.cn),
            ("cert_sha1", label.cert_sha1),
        ]),
    )
}

fn present<'a, const N: usize>(fields: [(&'a str, Option<&'a str>); N]) -> Vec<(&'a str, &'a str)> {
    fields
        .into_iter()
        .filter_map(|(name, value)| Some((name, value?)))
        .collect()
}

fn structured(kind: &str, fields: &[(&str, &str)]) -> String {
    let fields = form_urlencoded::Serializer::new(String::new())
        .append_pair("v", "1")
        .append_pair("type", kind)
        .extend_pairs(fields)
        .finish();
    format!("data:,{fields}")
}

pub(crate) fn with_server_exp(key_label: &str, server_exp: u64) -> String {
    let Some(label) = parse(key_label) else {
        return key_label.to_owned();
    };
    let fields = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            label
                .fields
                .iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("server_exp")),
        )
        .append_pair("server_exp", &server_exp.to_string())
        .finish();
    format!("data:,{fields}")
}

/// Parses a structured key label.
///
/// Returns `None` unless the label is a `data:` URL with `v=1` and a `type` field.
pub fn parse(key_label: &str) -> Option<KeyLabel> {
    let (scheme, rest) = key_label.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("data") {
        return None;
    }

    let (metadata, data) = rest.split_once(',').unwrap_or(("", rest));
    let data = if metadata.to_ascii_lowercase().ends_with(";base64") {
        Cow::Owned(BASE64.decode(data).ok()?)
    } else {
        Cow::Borrowed(data.as_bytes())
    };

    let fields = form_urlencoded::parse(&data)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let label = KeyLabel { fields };
    if label.field("v") != Some("1") || label.field("type").is_none() {
        return None;
    }
    Some(label)
}

/// Returns `true` if `key_label` is `name`, or is a structured label whose `label` field is
/// `name`.
pub fn matches(key_label: &str, name: &str) -> bool {
    key_label == name || parse(key_label).is_some_and(|label| label.field("label") == Some(name))
}
