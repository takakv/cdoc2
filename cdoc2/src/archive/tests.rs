use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use tar::{Builder, EntryType, Header};

use super::unpack::MAX_ENTRY_HEADERS_SIZE;
use super::{File, UnpackError, unpack};

const DATA: &[u8] = b"lorem ipsum";

fn compressed(tar: Vec<u8>) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

fn too_large_headers() -> UnpackError {
    UnpackError::Malformed(format!(
        "entry headers exceed {MAX_ENTRY_HEADERS_SIZE} bytes"
    ))
}

fn regular_header(size: u64) -> Header {
    let mut header = Header::new_ustar();
    header.set_entry_type(EntryType::Regular);
    header.set_size(size);
    header
}

// A tar with one file whose PAX header holds a comment of `comment_len` bytes.
fn with_pax_comment(comment_len: usize) -> Vec<u8> {
    let comment = vec![b'x'; comment_len];
    let mut builder = Builder::new(Vec::new());
    builder
        .append_pax_extensions([("comment", comment.as_slice())])
        .unwrap();
    builder
        .append_data(&mut regular_header(DATA.len() as u64), "a.txt", DATA)
        .unwrap();
    compressed(builder.into_inner().unwrap())
}

#[test]
fn pax_header_within_the_limit() {
    let mut files = Vec::new();
    unpack(with_pax_comment(32 * 1024).as_slice(), u64::MAX, &mut files).unwrap();
    assert_eq!(
        files,
        [File {
            name: "a.txt".into(),
            data: DATA.to_vec(),
        }]
    );
}

#[test]
fn pax_header_over_the_limit() {
    let mut files = Vec::new();
    let tar = with_pax_comment(MAX_ENTRY_HEADERS_SIZE as usize);
    let result = unpack(tar.as_slice(), u64::MAX, &mut files);
    assert_eq!(result, Err(too_large_headers()));
    assert!(files.is_empty());
}

#[test]
fn gnu_long_name_over_the_limit() {
    let name = "a".repeat(MAX_ENTRY_HEADERS_SIZE as usize);
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(DATA.len() as u64);
    let mut builder = Builder::new(Vec::new());
    builder.append_data(&mut header, &name, DATA).unwrap();
    let tar = compressed(builder.into_inner().unwrap());

    let mut files = Vec::new();
    let result = unpack(tar.as_slice(), u64::MAX, &mut files);
    assert_eq!(result, Err(too_large_headers()));
    assert!(files.is_empty());
}
