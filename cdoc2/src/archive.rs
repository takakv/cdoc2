use std::collections::HashSet;
use std::io::{self, Read, Take, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::bufread::ZlibDecoder;
use flate2::write::ZlibEncoder;
use tar::{EntryType, Header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnpackError {
    #[error("malformed archive: {0}")]
    Malformed(String),
    #[error("unpacked data exceeds the {0}-byte limit")]
    TooLarge(u64),
    #[error("archive entry {name:?} is not a regular file (tar type {entry_type:?})")]
    UnsupportedEntryType { name: String, entry_type: char },
    #[error(transparent)]
    FileName(#[from] FileNameError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileNameError {
    #[error("file name {0:?} is not allowed")]
    Unsafe(String),
    #[error("duplicate file name {0:?}")]
    Duplicate(String),
}

const BLOCK_SIZE: u64 = 512;
const USTAR_NAME_LEN: usize = 100;
const USTAR_MAX_SIZE: u64 = 0o777_7777_7777;
const IN_MEMORY: &str = "writing to memory should not fail";

pub fn unpack(compressed: &[u8], max_size: u64) -> Result<Vec<File>, UnpackError> {
    let mut reader = ZlibDecoder::new(compressed).take(max_size.saturating_add(1));
    let result = unpack_limited(&mut reader);
    if reader.limit() == 0 {
        return Err(UnpackError::TooLarge(max_size));
    }
    result
}

fn unpack_limited(reader: &mut Take<ZlibDecoder<&[u8]>>) -> Result<Vec<File>, UnpackError> {
    let files = read_files(&mut tar::Archive::new(&mut *reader))?;

    // https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html
    // "At the end of the archive file there shall be two 512-byte blocks filled with binary zeros,
    // interpreted as an end-of-archive indicator."
    //
    // Checking for one block is enough since the tar crate stops after reading the
    // first of the zero blocks, but we must still check the second one after.
    let zeros = read_zeros(reader)?;
    if !reader.get_ref().get_ref().is_empty() {
        return Err(trailing_data());
    }
    if zeros < BLOCK_SIZE {
        return Err(UnpackError::Malformed(
            "missing end-of-archive marker".to_owned(),
        ));
    }
    Ok(files)
}

fn read_files<R: Read>(archive: &mut tar::Archive<R>) -> Result<Vec<File>, UnpackError> {
    let mut files = Vec::new();
    let mut names = HashSet::new();

    for entry in archive.entries().map_err(malformed)? {
        let mut entry = entry.map_err(malformed)?;

        // tar skips PAX records it can't parse.
        if let Some(extensions) = entry.pax_extensions().map_err(malformed)? {
            for extension in extensions {
                extension.map_err(malformed)?;
            }
        }

        let path = entry.path_bytes().into_owned();
        match entry.header().entry_type() {
            EntryType::Regular => {}
            other => {
                return Err(UnpackError::UnsupportedEntryType {
                    name: String::from_utf8_lossy(&path).into_owned(),
                    entry_type: char::from(other.as_byte()),
                });
            }
        }

        let name = String::from_utf8(path).map_err(|e| {
            FileNameError::Unsafe(String::from_utf8_lossy(e.as_bytes()).into_owned())
        })?;
        check_file_name(&name, &mut names)?;

        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(malformed)?;
        files.push(File { name, data });
    }

    Ok(files)
}

fn read_zeros(reader: &mut impl Read) -> Result<u64, UnpackError> {
    let mut buf = [0u8; 4096];
    let mut total = 0;
    loop {
        let n = reader.read(&mut buf).map_err(malformed)?;
        if n == 0 {
            return Ok(total);
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Err(trailing_data());
        }
        total += n as u64;
    }
}

fn malformed(e: io::Error) -> UnpackError {
    UnpackError::Malformed(e.to_string())
}

fn trailing_data() -> UnpackError {
    UnpackError::Malformed("data after the end of the archive".to_owned())
}

pub fn pack(files: &[File]) -> Result<Vec<u8>, FileNameError> {
    let mut names = HashSet::new();
    for file in files {
        check_file_name(&file.name, &mut names)?;
    }

    let mtime = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut builder = tar::Builder::new(ZlibEncoder::new(Vec::new(), Compression::default()));
    for file in files {
        append_file(&mut builder, file, mtime).expect(IN_MEMORY);
    }
    Ok(builder
        .into_inner()
        .and_then(ZlibEncoder::finish)
        .expect(IN_MEMORY))
}

fn append_file(builder: &mut tar::Builder<impl Write>, file: &File, mtime: u64) -> io::Result<()> {
    let size = file.data.len() as u64;
    let size_record = size.to_string();

    let mut pax: Vec<(&str, &[u8])> = Vec::new();
    if !file.name.is_ascii() || file.name.len() > USTAR_NAME_LEN {
        pax.push(("path", file.name.as_bytes()));
    }
    if size > USTAR_MAX_SIZE {
        pax.push(("size", size_record.as_bytes()));
    }
    builder.append_pax_extensions(pax)?;

    // The ustar name is a fallback for readers without PAX support.
    let name = &file.name.as_bytes()[..file.name.len().min(USTAR_NAME_LEN)];

    let mut header = Header::new_ustar();
    header.as_ustar_mut().expect("header should be ustar").name[..name.len()].copy_from_slice(name);
    header.set_entry_type(EntryType::Regular);
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(mtime);
    header.set_cksum();
    builder.append(&header, file.data.as_slice())
}

const FORBIDDEN_CHARS: [char; 8] = ['<', '>', ':', '\\', '/', '|', '?', '*'];
const RESERVED_NAMES: [&str; 28] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³",
];
const RIGHT_TO_LEFT_OVERRIDE: char = '\u{202E}';

fn check_file_name(name: &str, seen: &mut HashSet<String>) -> Result<(), FileNameError> {
    if !is_valid_file_name(name) {
        return Err(FileNameError::Unsafe(name.to_owned()));
    }
    if !seen.insert(name.to_owned()) {
        return Err(FileNameError::Duplicate(name.to_owned()));
    }
    Ok(())
}

// https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
fn is_valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with([' ', '-'])
        && !name.ends_with([' ', '.'])
        && !is_reserved_name(name)
        && !name
            .chars()
            .any(|c| FORBIDDEN_CHARS.contains(&c) || c.is_control() || c == RIGHT_TO_LEFT_OVERRIDE)
}

fn is_reserved_name(name: &str) -> bool {
    let stem = name
        .split_once('.')
        .map_or(name, |(stem, _)| stem)
        .trim_end_matches(' ');
    RESERVED_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}
