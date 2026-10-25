use cdoc2::archive::File;
use cdoc2::capsule::ecc::EcSecretKey;
use cdoc2::container::Container;
use cdoc2::decrypt::{DecryptError, DecryptOptions, DecryptionKey, decrypt};
use cdoc2::header::RecipientId;

fn decrypt_reference_container(bytes: &[u8], id: RecipientId, key: DecryptionKey) -> Vec<File> {
    let container = Container::parse(bytes).unwrap();
    let record = container.head.header.find_recipient(id).unwrap();
    decrypt(&container, record, &key, DecryptOptions::default()).unwrap()
}

fn lorem_ipsum() -> Vec<File> {
    vec![File {
        name: "loremipsum.txt".into(),
        data: include_bytes!("data/loremipsum.txt").to_vec(),
    }]
}

#[test]
fn symmetric_key() {
    let container = include_bytes!("data/ref-symmetric.cdoc2");
    let id = RecipientId::Symmetric { label: "label" };
    let files = decrypt_reference_container(container, id, DecryptionKey::Symmetric(&[1; 32]));
    assert_eq!(files, lorem_ipsum());
}

#[test]
fn password() {
    let container = include_bytes!("data/ref-password.cdoc2");
    let id = RecipientId::Password { label: "label" };
    let files = decrypt_reference_container(container, id, DecryptionKey::Password("Salasõna123"));
    assert_eq!(files, lorem_ipsum());
}

#[test]
fn password_iteration_cap() {
    let container = Container::parse(include_bytes!("data/ref-password.cdoc2")).unwrap();
    let record = &container.head.header.recipients[0];
    let options = DecryptOptions {
        max_kdf_iterations: 599_999,
        ..Default::default()
    };
    let key = DecryptionKey::Password("Salasõna123");
    assert_eq!(
        decrypt(&container, record, &key, options),
        Err(DecryptError::TooManyKdfIterations {
            iterations: 600_000,
            max: 599_999,
        })
    );
}

#[test]
fn ec_key() {
    let pem = include_str!("data/ref-ec-key.pem");
    let key = EcSecretKey::P384(p384::SecretKey::from_sec1_pem(pem).unwrap());
    let container = include_bytes!("data/ref-ec.cdoc2");
    let id = RecipientId::EcPublicKey(&key.public_key());
    let files = decrypt_reference_container(container, id, DecryptionKey::EcSecretKey(&key));
    assert_eq!(files, lorem_ipsum());
}
