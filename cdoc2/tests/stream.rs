use std::io::{self, Cursor};

use cdoc2::archive::{File, FileEntry};
use cdoc2::container::ContainerHead;
use cdoc2::decrypt::{DecryptError, DecryptionKey, decrypt_into};
use cdoc2::encrypt::{EncryptError, Recipient, encrypt_into};
use cdoc2::payload::PayloadError;

const KEY: &[u8; 32] = &[1; 32];
const RECIPIENT: Recipient = Recipient::Symmetric {
    key_label: "label",
    key: KEY,
};

fn files() -> Vec<File> {
    vec![
        File {
            name: "a.txt".into(),
            data: b"lorem ipsum".to_vec(),
        },
        File {
            name: "b.bin".into(),
            data: (0..200_000).map(|i| i as u8).collect(),
        },
    ]
}

fn encrypt_files(files: &[File]) -> Vec<u8> {
    let entries: Vec<_> = files
        .iter()
        .map(|file| FileEntry {
            name: &file.name,
            size: file.data.len() as u64,
        })
        .collect();
    let mut container = Vec::new();
    encrypt_into(
        &entries,
        |i| Ok(Cursor::new(&files[i].data)),
        &[RECIPIENT],
        &mut container,
    )
    .unwrap();
    container
}

fn decrypt_files(container: &[u8]) -> (Result<(), DecryptError>, Vec<File>) {
    let mut reader = Cursor::new(container);
    let head = ContainerHead::read(&mut reader).unwrap();
    let mut files = Vec::new();
    let result = decrypt_into(
        &head,
        &head.header.recipients[0],
        &DecryptionKey::Symmetric(KEY),
        reader,
        u64::MAX,
        &mut files,
    );
    (result, files)
}

#[test]
fn round_trip() {
    let files = files();
    let (result, decrypted) = decrypt_files(&encrypt_files(&files));
    assert_eq!(result, Ok(()));
    assert_eq!(decrypted, files);
}

#[test]
fn tampered_payload_never_reaches_the_sink() {
    let mut container = encrypt_files(&files());
    let near_the_end = container.len() - 100;
    container[near_the_end] ^= 1;

    let (result, decrypted) = decrypt_files(&container);
    assert_eq!(
        result,
        Err(DecryptError::Payload(PayloadError::DecryptionFailed))
    );
    assert!(decrypted.is_empty());
}

#[test]
fn size_must_match_the_data() {
    for size in [10, 12] {
        let entries = [FileEntry {
            name: "a.txt",
            size,
        }];
        let result = encrypt_into(
            &entries,
            |_| Ok(b"lorem ipsum".as_slice()),
            &[RECIPIENT],
            io::sink(),
        );
        assert_eq!(result, Err(EncryptError::SizeChanged("a.txt".into())));
    }
}
