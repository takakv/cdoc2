use std::thread::{self, JoinHandle};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use tiny_http::{Header, Response, Server};

use cdoc2::archive::File;
use cdoc2::capsule::Capsule;
use cdoc2::capsule::ecc::{EcPublicKey, EcSecretKey};
use cdoc2::container::Container;
use cdoc2::decrypt::{DecryptionKey, decrypt};
use cdoc2::encrypt::Recipient;
use cdoc2_client::{Client, KeyServer};

fn files() -> Vec<File> {
    vec![File {
        name: "a.txt".into(),
        data: b"lorem ipsum".to_vec(),
    }]
}

// Accepts one capsule upload as transaction KC0123 and returns the uploaded JSON.
fn fake_server() -> (KeyServer, JoinHandle<Value>) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let upload = thread::spawn(move || {
        let mut request = server.recv().unwrap();
        assert_eq!(request.url(), "/key-capsules");
        let body = serde_json::from_reader(request.as_reader()).unwrap();
        let location: Header = "Location: /key-capsules/KC0123".parse().unwrap();
        request
            .respond(Response::empty(201).with_header(location))
            .unwrap();
        body
    });
    let server = KeyServer {
        id: "test".into(),
        upload_url: url.clone(),
        fetch_url: url,
    };
    (server, upload)
}

#[test]
fn uploads_capsules_while_preparing() {
    let (server, upload) = fake_server();
    let secret_key = p384::SecretKey::from_slice(&[1; 48]).unwrap();
    let public_key = EcPublicKey::P384(secret_key.public_key());
    let recipient = Recipient::KeyServer {
        key_label: "label",
        public_key: &public_key,
        keyserver_id: "test",
    };

    let client = Client::new(vec![server]).unwrap();
    let prepared = client.prepare(&[recipient]).unwrap();
    let bytes = prepared.encrypt(&files()).unwrap();
    let upload = upload.join().unwrap();

    let container = Container::parse(&bytes).unwrap();
    let record = &container.head.header.recipients[0];
    let Capsule::KeyServer(capsule) = &record.capsule else {
        panic!("expected a key server capsule");
    };
    assert_eq!(capsule.transaction_id, "KC0123");
    assert_eq!(upload["capsule_type"], "ecc_secp384r1");
    assert_eq!(
        upload["recipient_id"],
        STANDARD.encode(&capsule.recipient_public_key)
    );

    // The uploaded ephemeral key is the one that decrypts the container.
    let ephemeral_key = upload["ephemeral_key_material"].as_str().unwrap();
    let fetched = record.with_sender_public_key(STANDARD.decode(ephemeral_key).unwrap());
    let key = EcSecretKey::P384(secret_key);
    let decrypted = decrypt(
        &container,
        &fetched.unwrap(),
        &DecryptionKey::EcSecretKey(&key),
        u64::MAX,
    );
    assert_eq!(decrypted, Ok(files()));
}
