use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tiny_http::{Header, Method, Response, Server};

use cdoc2::archive::File;
use cdoc2::capsule::ecc::{EcSecretKey, EllipticCurve};
use cdoc2::container::Container;
use cdoc2::decrypt::{DecryptionKey, decrypt};
use cdoc2::encrypt::Recipient;
use cdoc2::key_label::{self, CertLabel};
use cdoc2_client::{Client, EcdsaSigner, KeyServer, TlsIdentity};

fn files() -> Vec<File> {
    vec![File {
        name: "a.txt".into(),
        data: b"lorem ipsum".to_vec(),
    }]
}

fn secret_key() -> EcSecretKey {
    EcSecretKey::P384(p384::SecretKey::from_slice(&[1; 48]).unwrap())
}

fn fake_server(
    upload_headers: &'static [&'static str],
    requests: usize,
) -> (KeyServer, JoinHandle<Vec<Option<String>>>) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let handle = thread::spawn(move || {
        let mut capsule = String::new();
        let mut requested_expiries = Vec::new();
        for _ in 0..requests {
            let mut request = server.recv().unwrap();
            if *request.method() == Method::Post {
                assert_eq!(request.url(), "/key-capsules");
                let expiry = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("x-expiry-time"))
                    .map(|header| header.value.to_string());
                requested_expiries.push(expiry);
                capsule.clear();
                request.as_reader().read_to_string(&mut capsule).unwrap();

                let location: Header = "Location: /key-capsules/KC0123".parse().unwrap();
                let mut response = Response::empty(201).with_header(location);
                for header in upload_headers {
                    response = response.with_header(header.parse::<Header>().unwrap());
                }
                request.respond(response).unwrap();
            } else {
                assert_eq!(request.url(), "/key-capsules/KC0123");
                request.respond(Response::from_string(&capsule)).unwrap();
            }
        }
        requested_expiries
    });
    let server = KeyServer {
        id: "test".into(),
        upload_url: url.clone(),
        fetch_url: url,
    };
    (server, handle)
}

// The fake server uses HTTP so the client never signs.
#[derive(Debug)]
struct UnusedSigner;

impl EcdsaSigner for UnusedSigner {
    fn curve(&self) -> EllipticCurve {
        EllipticCurve::Secp384r1
    }

    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("unused".into())
    }
}

#[test]
fn round_trip() {
    let upload_headers = &[
        "x-expiry-time: 2029-01-01T00:00:00Z",
        "x-expiry-time-adjusted: true",
    ];
    let (server, server_thread) = fake_server(upload_headers, 2);

    let century = Duration::from_secs(100 * 365 * 24 * 60 * 60);
    let client = Client::new(vec![server]).with_capsule_lifetime(century);

    let key = secret_key();
    let public_key = key.public_key();
    let key_label = key_label::cert(&CertLabel {
        file: "cert.pem",
        cn: None,
        cert_sha1: None,
    });
    let recipient = Recipient::KeyServer {
        key_label: &key_label,
        public_key: &public_key,
        keyserver_id: "test",
        not_after: Some(1893456000), // 2030-01-01
    };

    let mut prepared = client.prepare(&[recipient]).unwrap();
    let upload = prepared.capsule_uploads().next().unwrap();
    assert_eq!(upload.expiry(), Some(1861920000)); // 2029-01-01
    assert!(upload.expiry_adjusted());

    let bytes = prepared.encrypt(&files()).unwrap();
    let container = Container::parse(&bytes).unwrap();
    let record = &container.head.header.recipients[0];
    let label = key_label::parse(&record.key_label).unwrap();
    assert_eq!(label.field("file"), Some("cert.pem"));
    assert_eq!(label.field("server_exp"), Some("1861920000"));

    let fetched = client
        .fetch(
            record,
            &TlsIdentity::with_signer(Vec::new(), Arc::new(UnusedSigner)),
        )
        .unwrap();

    let decrypted = decrypt(
        &container,
        &fetched,
        &DecryptionKey::EcSecretKey(&key),
        u64::MAX,
    );
    assert_eq!(decrypted, Ok(files()));

    let requested = server_thread.join().unwrap();
    assert_eq!(requested, [Some("2030-01-01T00:00:00Z".to_owned())]);
}

#[test]
fn lifetime() {
    let requested_expiry = |lifetime: Option<Duration>| {
        let (server, server_thread) = fake_server(&[], 1);
        let mut client = Client::new(vec![server]);
        if let Some(lifetime) = lifetime {
            client = client.with_capsule_lifetime(lifetime);
        }
        let public_key = secret_key().public_key();
        let recipient = Recipient::KeyServer {
            key_label: "label",
            public_key: &public_key,
            keyserver_id: "test",
            not_after: None,
        };
        client.prepare(&[recipient]).unwrap();
        server_thread.join().unwrap().pop().unwrap()
    };
    let now = || jiff::Timestamp::now().as_second();

    assert_eq!(requested_expiry(None), None);

    let day = Duration::from_secs(24 * 60 * 60);
    let earliest = now() + 86400;
    let requested = requested_expiry(Some(day)).unwrap();
    let latest = now() + 86400;
    let requested = requested.parse::<jiff::Timestamp>().unwrap().as_second();
    assert!((earliest..=latest).contains(&requested));
}
