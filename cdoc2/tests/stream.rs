use std::io::{self, Cursor};

use cdoc2::archive::{File, FileEntry, Sink, UnpackError};
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
    let entries: Vec<FileEntry> = files.iter().map(FileEntry::from).collect();
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

#[derive(Debug, Default)]
struct Recorder {
    files: Vec<Recorded>,
}

#[derive(Debug)]
struct Recorded {
    name: String,
    size: u64,
    data: Vec<u8>,
    finished: bool,
}

impl Sink for Recorder {
    fn create_file(&mut self, name: &str, size: u64) -> io::Result<()> {
        assert!(self.files.iter().all(|file| file.finished));
        self.files.push(Recorded {
            name: name.to_owned(),
            size,
            data: Vec::new(),
            finished: false,
        });
        Ok(())
    }

    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let file = self.files.last_mut().unwrap();
        assert!(!file.finished);
        file.data.extend_from_slice(data);
        Ok(())
    }

    fn finish_file(&mut self) -> io::Result<()> {
        self.files.last_mut().unwrap().finished = true;
        Ok(())
    }
}

fn decrypt_recorded(container: &[u8], max_size: u64) -> (Result<(), DecryptError>, Recorder) {
    let mut reader = Cursor::new(container);
    let head = ContainerHead::read(&mut reader).unwrap();
    let mut recorder = Recorder::default();
    let result = decrypt_into(
        &head,
        &head.header.recipients[0],
        &DecryptionKey::Symmetric(KEY),
        reader,
        max_size,
        &mut recorder,
    );
    (result, recorder)
}

#[test]
fn sink_gets_sizes_and_ends() {
    let files = files();
    let (result, recorder) = decrypt_recorded(&encrypt_files(&files), u64::MAX);
    assert_eq!(result, Ok(()));
    assert_eq!(recorder.files.len(), files.len());
    for (recorded, file) in recorder.files.iter().zip(&files) {
        assert_eq!(recorded.name, file.name);
        assert_eq!(recorded.size, file.data.len() as u64);
        assert_eq!(recorded.data, file.data);
        assert!(recorded.finished);
    }
}

#[test]
fn oversized_file_never_reaches_the_sink() {
    let (result, recorder) = decrypt_recorded(&encrypt_files(&files()), 100_000);
    assert_eq!(
        result,
        Err(DecryptError::Unpack(UnpackError::TooLarge(100_000)))
    );
    let names: Vec<&str> = recorder
        .files
        .iter()
        .map(|file| file.name.as_str())
        .collect();
    assert_eq!(names, ["a.txt"]);
}
