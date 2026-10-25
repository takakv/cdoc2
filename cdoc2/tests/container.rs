use std::io;

use cdoc2::archive::File;
use cdoc2::container::{Container, ContainerError, ContainerHead};
use cdoc2::encrypt::{Recipient, encrypt};
use cdoc2::header::HeaderError;

const PRELUDE: &[u8] = b"CDOC";
const HMAC_LEN: usize = 32;
const MAX_HEADER_LEN: i32 = 1 << 20;

fn container_bytes() -> Vec<u8> {
    let files = [File {
        name: "a.txt".into(),
        data: b"lorem ipsum".to_vec(),
    }];
    let recipient = Recipient::Symmetric {
        key_label: "label",
        key: &[1; 32],
    };
    encrypt(&files, &[recipient]).unwrap()
}

fn head_len(bytes: &[u8]) -> usize {
    let header_len = i32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
    9 + header_len + HMAC_LEN
}

#[test]
fn parse_and_read_agree() {
    let bytes = container_bytes();
    let container = Container::parse(&bytes).unwrap();

    let mut reader = bytes.as_slice();
    let head = ContainerHead::read(&mut reader).unwrap();

    assert_eq!(head, container.head);
    assert_eq!(reader, container.payload);
    assert_eq!(container.payload, &bytes[head_len(&bytes)..]);
}

#[test]
fn truncated() {
    let bytes = container_bytes();
    let head_len = head_len(&bytes);

    for len in 0..PRELUDE.len() {
        let result = Container::parse(&bytes[..len]);
        assert_eq!(
            result.unwrap_err(),
            ContainerError::NotCdoc2,
            "length {len}"
        );
    }
    for len in PRELUDE.len()..head_len {
        let result = Container::parse(&bytes[..len]);
        assert_eq!(
            result.unwrap_err(),
            ContainerError::Truncated,
            "length {len}"
        );
    }
    assert!(
        Container::parse(&bytes[..head_len])
            .unwrap()
            .payload
            .is_empty()
    );
}

#[test]
fn invalid_fields() {
    let bytes = container_bytes();
    let with = |offset: usize, replacement: &[u8]| {
        let mut modified = bytes.clone();
        modified[offset..offset + replacement.len()].copy_from_slice(replacement);
        Container::parse(&modified).unwrap_err()
    };

    assert_eq!(with(0, b"CDOX"), ContainerError::NotCdoc2);
    assert_eq!(with(4, &[1]), ContainerError::UnsupportedVersion(1));
    assert_eq!(
        with(5, &(-1i32).to_be_bytes()),
        ContainerError::InvalidHeaderLength
    );
    let too_long = (MAX_HEADER_LEN + 1).to_be_bytes();
    assert_eq!(with(5, &too_long), ContainerError::InvalidHeaderLength);
    assert!(matches!(with(9, &[0xff; 8]), ContainerError::Header(_)));
}

#[test]
fn no_recipients() {
    let header = [8, 0, 0, 0, 4, 0, 4, 0, 4, 0, 0, 0]; // an empty flatbuffer table
    let header_len = (header.len() as i32).to_be_bytes();
    let bytes = [PRELUDE, &[2], &header_len, &header, &[0; HMAC_LEN]].concat();

    assert_eq!(
        Container::parse(&bytes).unwrap_err(),
        ContainerError::Header(HeaderError::Malformed("no recipients".into()))
    );
}

#[test]
fn read_error() {
    struct Failing;
    impl io::Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
    }

    assert_eq!(
        ContainerHead::read(&mut Failing).unwrap_err(),
        ContainerError::Read("disk on fire".into())
    );
}
