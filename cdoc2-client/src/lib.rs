use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use cdoc2::capsule::Capsule;
use cdoc2::capsule::ecc::EllipticCurve;
use cdoc2::capsule::key_server::CapsuleUpload;
use cdoc2::encrypt::{self, EncryptError, PreparedEncryption, Recipient};
use cdoc2::header::RecipientRecord;

mod tls;

use tls::http_client;
pub use tls::{EcdsaSigner, TlsIdentity};

pub const RIA_KEYSERVER_ID: &str = "00000000-0000-0000-0000-000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyServer {
    pub id: String,
    pub upload_url: String,
    pub fetch_url: String,
}

impl KeyServer {
    pub fn ria() -> KeyServer {
        KeyServer {
            id: RIA_KEYSERVER_ID.to_owned(),
            upload_url: "https://cdoc2.id.ee:8443".to_owned(),
            fetch_url: "https://cdoc2.id.ee:8444".to_owned(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Encrypt(#[from] EncryptError),
    #[error("no configuration for key server {0:?}")]
    UnknownKeyServer(String),
    #[error("the recipient's key capsule is not on a key server")]
    NotKeyServerRecipient,
    #[error("invalid transaction ID {0:?}")]
    InvalidTransactionId(String),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("the key server sent an invalid response: {0}")]
    InvalidResponse(&'static str),
}

pub struct Client {
    servers: Vec<KeyServer>,
    capsule_lifetime: Option<Duration>,
}

impl Client {
    pub fn new(servers: Vec<KeyServer>) -> Client {
        Client {
            servers,
            capsule_lifetime: None,
        }
    }

    pub fn with_capsule_lifetime(mut self, lifetime: Duration) -> Client {
        self.capsule_lifetime = Some(lifetime);
        self
    }

    /// Like [`cdoc2::encrypt::prepare`], but also uploads the capsules of key server recipients,
    /// so that the result is ready to encrypt.
    pub fn prepare(&self, recipients: &[Recipient]) -> Result<PreparedEncryption, Error> {
        let mut prepared = encrypt::prepare(recipients)?;
        if prepared.capsule_uploads().next().is_some() {
            let http = http_client(None)?;
            for capsule in prepared.capsule_uploads() {
                self.upload(&http, capsule)?;
            }
        }
        Ok(prepared)
    }

    fn upload(
        &self,
        http: &reqwest::blocking::Client,
        capsule: &mut CapsuleUpload,
    ) -> Result<(), Error> {
        let server = self.server(capsule.keyserver_id())?;
        let body = serde_json::json!({
            "recipient_id": STANDARD.encode(capsule.recipient_public_key()),
            "ephemeral_key_material": STANDARD.encode(capsule.sender_public_key()),
            "capsule_type": capsule_type(capsule.curve()),
        });

        let url = capsules_url(&server.upload_url);
        let mut request = http.post(url).json(&body);
        if let Some(expiry) = self.requested_expiry(capsule) {
            request = request.header("x-expiry-time", format_expiry(expiry));
        }
        let response = request.send()?.error_for_status()?;

        let header = |name: &str| response.headers().get(name)?.to_str().ok();
        let location =
            header("location").and_then(|location| location.rsplit_once("/key-capsules/"));
        let transaction_id = match location {
            Some((_, id)) if is_valid_transaction_id(id) => id.to_owned(),
            _ => return Err(Error::InvalidResponse("no transaction ID in Location")),
        };
        let expiry = header("x-expiry-time").map(parse_expiry).transpose()?;
        let adjusted = header("x-expiry-time-adjusted")
            .map_or(Ok(false), str::parse)
            .map_err(|_| Error::InvalidResponse("invalid x-expiry-time-adjusted"))?;

        capsule.set_transaction_id(transaction_id);
        if let Some(expiry) = expiry {
            capsule.set_expiry(expiry, adjusted);
        }
        Ok(())
    }

    fn requested_expiry(&self, capsule: &CapsuleUpload) -> Option<u64> {
        let lifetime_end = self.capsule_lifetime.map(|lifetime| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            now.saturating_add(lifetime).as_secs()
        });
        [lifetime_end, capsule.not_after()]
            .into_iter()
            .flatten()
            .min()
    }

    pub fn fetch(
        &self,
        record: &RecipientRecord,
        identity: &TlsIdentity,
    ) -> Result<RecipientRecord, Error> {
        let Capsule::KeyServer(capsule) = &record.capsule else {
            return Err(Error::NotKeyServerRecipient);
        };
        let server = self.server(&capsule.keyserver_id)?;
        let transaction_id = &capsule.transaction_id;
        if !is_valid_transaction_id(transaction_id) {
            return Err(Error::InvalidTransactionId(transaction_id.clone()));
        }

        let url = format!("{}/{transaction_id}", capsules_url(&server.fetch_url));
        let response = http_client(Some(identity))?
            .get(url)
            .send()?
            .error_for_status()?;
        let body: Value = response.json()?;

        let recipient_id = decode_field(&body, "recipient_id")?;
        let sender_public_key = decode_field(&body, "ephemeral_key_material")?;
        if body["capsule_type"] != capsule_type(capsule.curve)
            || recipient_id != capsule.recipient_public_key
        {
            return Err(Error::InvalidResponse(
                "the capsule is for another recipient",
            ));
        }

        Ok(record
            .with_sender_public_key(sender_public_key)
            .expect("the record has a key server capsule"))
    }

    fn server(&self, id: &str) -> Result<&KeyServer, Error> {
        self.servers
            .iter()
            .find(|server| server.id == id)
            .ok_or_else(|| Error::UnknownKeyServer(id.to_owned()))
    }
}

fn capsule_type(curve: EllipticCurve) -> &'static str {
    match curve {
        EllipticCurve::Secp256r1 => "ecc_secp256r1",
        EllipticCurve::Secp384r1 => "ecc_secp384r1",
        EllipticCurve::Secp521r1 => "ecc_secp521r1",
    }
}

fn is_valid_transaction_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn format_expiry(expiry: u64) -> String {
    let max = jiff::Timestamp::MAX.as_second();
    let second = i64::try_from(expiry).map_or(max, |second| second.min(max));
    jiff::Timestamp::from_second(second)
        .expect("the second is in range")
        .to_string()
}

fn parse_expiry(value: &str) -> Result<u64, Error> {
    value
        .parse::<jiff::Timestamp>()
        .ok()
        .and_then(|time| u64::try_from(time.as_second()).ok())
        .ok_or(Error::InvalidResponse("invalid x-expiry-time"))
}

fn decode_field(body: &Value, name: &str) -> Result<Vec<u8>, Error> {
    body[name]
        .as_str()
        .and_then(|value| STANDARD.decode(value).ok())
        .ok_or(Error::InvalidResponse("a field is missing or not base64"))
}

fn capsules_url(server_url: &str) -> String {
    format!("{}/key-capsules", server_url.trim_end_matches('/'))
}
