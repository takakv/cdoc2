use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::LOCATION;

use cdoc2::capsule::ecc::EllipticCurve;
use cdoc2::capsule::key_server::CapsuleUpload;
use cdoc2::encrypt::{self, EncryptError, PreparedEncryption, Recipient};

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
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("the key server returned no usable transaction ID")]
    InvalidTransactionId,
}

pub struct Client {
    http: reqwest::blocking::Client,
    servers: Vec<KeyServer>,
}

impl Client {
    pub fn new(servers: Vec<KeyServer>) -> Result<Client, Error> {
        let http = reqwest::blocking::Client::builder().build()?;
        Ok(Client { http, servers })
    }

    /// Like [`cdoc2::encrypt::prepare`], but also uploads the capsules of key server recipients,
    /// so that the result is ready to encrypt.
    pub fn prepare(&self, recipients: &[Recipient]) -> Result<PreparedEncryption, Error> {
        let mut prepared = encrypt::prepare(recipients)?;
        for capsule in prepared.capsule_uploads() {
            capsule.set_transaction_id(self.upload(capsule)?);
        }
        Ok(prepared)
    }

    pub fn upload(&self, capsule: &CapsuleUpload) -> Result<String, Error> {
        let server = self.server(capsule.keyserver_id())?;
        let body = serde_json::json!({
            "recipient_id": STANDARD.encode(capsule.recipient_public_key()),
            "ephemeral_key_material": STANDARD.encode(capsule.sender_public_key()),
            "capsule_type": capsule_type(capsule.curve()),
        });
        let url = format!("{}/key-capsules", server.upload_url.trim_end_matches('/'));
        let response = self.http.post(url).json(&body).send()?.error_for_status()?;
        response
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(transaction_id)
            .map(str::to_owned)
            .ok_or(Error::InvalidTransactionId)
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

fn transaction_id(location: &str) -> Option<&str> {
    let (_, id) = location.rsplit_once("/key-capsules/")?;
    let valid = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    valid.then_some(id)
}
