use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLabel {
    fields: Vec<(String, String)>,
}

impl KeyLabel {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub fn symmetric(label: &str) -> String {
    structured("secret", &[("label", label)])
}

pub fn password(label: &str) -> String {
    structured("pw", &[("label", label)])
}

pub fn public_key(file: &str, label: Option<&str>) -> String {
    match label {
        Some(label) => structured("pub_key", &[("file", file), ("label", label)]),
        None => structured("pub_key", &[("file", file)]),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EidLabel<'a> {
    pub eid_type: EidType,
    pub cn: &'a str,
    pub serial_number: &'a str,
    pub first_name: Option<&'a str>,
    pub last_name: Option<&'a str>,
    pub server_exp: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertLabel<'a> {
    pub file: &'a str,
    pub cn: Option<&'a str>,
    pub cert_sha1: Option<&'a str>,
    pub server_exp: Option<u64>,
}

pub fn eid(label: &EidLabel) -> String {
    let server_exp = label.server_exp.map(|t| t.to_string());
    structured(
        label.eid_type.as_str(),
        &present([
            ("serial_number", Some(label.serial_number)),
            ("cn", Some(label.cn)),
            ("first_name", label.first_name),
            ("last_name", label.last_name),
            ("server_exp", server_exp.as_deref()),
        ]),
    )
}

pub fn cert(label: &CertLabel) -> String {
    let server_exp = label.server_exp.map(|t| t.to_string());
    structured(
        "cert",
        &present([
            ("file", Some(label.file)),
            ("cn", label.cn),
            ("cert_sha1", label.cert_sha1),
            ("server_exp", server_exp.as_deref()),
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
    Some(KeyLabel { fields })
}

pub fn matches(key_label: &str, name: &str) -> bool {
    key_label == name || parse(key_label).is_some_and(|label| label.field("label") == Some(name))
}
