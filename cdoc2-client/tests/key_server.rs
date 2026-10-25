use std::thread::{self, JoinHandle};

use tiny_http::{Header, Response, Server};

use cdoc2::archive::File;
use cdoc2::capsule::ecc::{EcPublicKey, EcSecretKey};
use cdoc2::container::Container;
use cdoc2::decrypt::{DecryptionKey, decrypt};
use cdoc2::encrypt::Recipient;
use cdoc2_client::{Client, KeyServer, TlsIdentity};

fn files() -> Vec<File> {
    vec![File {
        name: "a.txt".into(),
        data: b"lorem ipsum".to_vec(),
    }]
}

// Stores one uploaded capsule as transaction KC0123 and serves it back once.
fn fake_server() -> (KeyServer, JoinHandle<()>) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let handle = thread::spawn(move || {
        let mut upload = server.recv().unwrap();
        assert_eq!(upload.url(), "/key-capsules");
        let mut capsule = String::new();
        upload.as_reader().read_to_string(&mut capsule).unwrap();
        let location: Header = "Location: /key-capsules/KC0123".parse().unwrap();
        upload
            .respond(Response::empty(201).with_header(location))
            .unwrap();

        let fetch = server.recv().unwrap();
        assert_eq!(fetch.url(), "/key-capsules/KC0123");
        fetch.respond(Response::from_string(capsule)).unwrap();
    });
    let server = KeyServer {
        id: "test".into(),
        upload_url: url.clone(),
        fetch_url: url,
    };
    (server, handle)
}

fn tls_identity() -> TlsIdentity {
    let client = rcgen::generate_simple_self_signed(["client".to_owned()]).unwrap();
    TlsIdentity::new(
        vec![client.cert.der().to_vec()],
        client.signing_key.serialize_der(),
    )
    .unwrap()
}

#[test]
fn round_trip() {
    let (server, server_thread) = fake_server();
    let client = Client::new(vec![server]);
    let secret_key = p384::SecretKey::from_slice(&[1; 48]).unwrap();
    let public_key = EcPublicKey::P384(secret_key.public_key());
    let recipient = Recipient::KeyServer {
        key_label: "label",
        public_key: &public_key,
        keyserver_id: "test",
    };

    let prepared = client.prepare(&[recipient]).unwrap();
    let bytes = prepared.encrypt(&files()).unwrap();
    let container = Container::parse(&bytes).unwrap();
    let record = &container.head.header.recipients[0];
    let fetched = client.fetch(record, &tls_identity()).unwrap();

    let key = EcSecretKey::P384(secret_key);
    let decrypted = decrypt(
        &container,
        &fetched,
        &DecryptionKey::EcSecretKey(&key),
        u64::MAX,
    );
    assert_eq!(decrypted, Ok(files()));
    server_thread.join().unwrap();
}
