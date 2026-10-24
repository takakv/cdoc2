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
    structured("secret", label)
}

pub fn password(label: &str) -> String {
    structured("pw", label)
}

fn structured(kind: &str, label: &str) -> String {
    let fields = form_urlencoded::Serializer::new(String::new())
        .append_pair("v", "1")
        .append_pair("type", kind)
        .append_pair("label", label)
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
