use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Take, Write};

use flate2::Compression;
use flate2::bufread::ZlibDecoder;
use flate2::write::ZlibEncoder;
use tar::{EntryType, Header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub name: &'a str,
    pub size: u64,
}

pub trait Sink {
    fn create_file(&mut self, name: &str) -> io::Result<()>;
    fn append(&mut self, data: &[u8]) -> io::Result<()>;
}

impl Sink for Vec<File> {
    fn create_file(&mut self, name: &str) -> io::Result<()> {
        self.push(File {
            name: name.to_owned(),
            data: Vec::new(),
        });
        Ok(())
    }

    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let file = self
            .last_mut()
            .expect("unpack creates a file before appending");
        file.data.extend_from_slice(data);
        Ok(())
    }
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
    #[error("cannot write unpacked file: {0}")]
    Write(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileNameError {
    #[error("file name {0:?} is not allowed")]
    Unsafe(String),
    #[error("duplicate file name {0:?}")]
    Duplicate(String),
}

const BLOCK_SIZE: u64 = 512;

pub fn unpack(
    compressed: impl Read,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), UnpackError> {
    let mut reader = ZlibDecoder::new(BufReader::new(compressed)).take(max_size.saturating_add(1));
    let result = unpack_limited(&mut reader, sink);
    if reader.limit() == 0 {
        return Err(UnpackError::TooLarge(max_size));
    }
    result
}

fn unpack_limited(
    reader: &mut Take<ZlibDecoder<impl BufRead>>,
    sink: &mut impl Sink,
) -> Result<(), UnpackError> {
    read_files(&mut tar::Archive::new(&mut *reader), sink)?;

    // https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html
    // "At the end of the archive file there shall be two 512-byte blocks filled with binary zeros,
    // interpreted as an end-of-archive indicator."
    //
    // Checking for one block is enough since the tar crate stops after reading the
    // first of the zero blocks, but we must still check the second one after.
    let zeros = read_zeros(reader)?;
    let compressed_rest = reader.get_mut().get_mut().fill_buf().map_err(malformed)?;
    if !compressed_rest.is_empty() {
        return Err(trailing_data());
    }
    if zeros < BLOCK_SIZE {
        return Err(UnpackError::Malformed(
            "missing end-of-archive marker".to_owned(),
        ));
    }
    Ok(())
}

fn read_files(
    archive: &mut tar::Archive<impl Read>,
    sink: &mut impl Sink,
) -> Result<(), UnpackError> {
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

        sink.create_file(&name).map_err(write_error)?;
        copy_to_sink(&mut entry, sink)?;
    }

    Ok(())
}

fn copy_to_sink(entry: &mut impl Read, sink: &mut impl Sink) -> Result<(), UnpackError> {
    let mut buf = [0; 8192];
    loop {
        let n = entry.read(&mut buf).map_err(malformed)?;
        if n == 0 {
            return Ok(());
        }
        sink.append(&buf[..n]).map_err(write_error)?;
    }
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

fn write_error(e: io::Error) -> UnpackError {
    UnpackError::Write(e.to_string())
}

fn trailing_data() -> UnpackError {
    UnpackError::Malformed("data after the end of the archive".to_owned())
}

const USTAR_NAME_LEN: usize = 100;
const USTAR_MAX_SIZE: u64 = 0o777_7777_7777;
const COPY_SIZE: usize = 64 * 1024;

pub(crate) enum PackError {
    Read { name: String, error: io::Error },
    SizeChanged(String),
    Write(io::Error),
}

impl From<io::Error> for PackError {
    fn from(error: io::Error) -> Self {
        PackError::Write(error)
    }
}

pub(crate) fn check_file_names(files: &[FileEntry]) -> Result<(), FileNameError> {
    let mut names = HashSet::new();
    for file in files {
        check_file_name(file.name, &mut names)?;
    }
    Ok(())
}

pub(crate) fn pack<R: Read, W: Write>(
    files: &[FileEntry],
    mut open: impl FnMut(usize) -> io::Result<R>,
    out: W,
) -> Result<W, PackError> {
    let mut builder = tar::Builder::new(ZlibEncoder::new(out, Compression::default()));
    for (i, file) in files.iter().enumerate() {
        let mut data = open(i).map_err(|error| read_error(file, error))?;
        append_headers(&mut builder, file)?;
        append_data(builder.get_mut(), file, &mut data)?;
    }
    Ok(builder.into_inner()?.finish()?)
}

fn append_headers(builder: &mut tar::Builder<impl Write>, file: &FileEntry) -> io::Result<()> {
    let size_record = file.size.to_string();

    let mut pax: Vec<(&str, &[u8])> = Vec::new();
    if !file.name.is_ascii() || file.name.len() > USTAR_NAME_LEN {
        pax.push(("path", file.name.as_bytes()));
    }
    if file.size > USTAR_MAX_SIZE {
        pax.push(("size", size_record.as_bytes()));
    }
    builder.append_pax_extensions(pax)?;

    // The ustar name is a fallback for readers without PAX support.
    let name = &file.name.as_bytes()[..file.name.len().min(USTAR_NAME_LEN)];

    let mut header = Header::new_ustar();
    header.as_ustar_mut().expect("header should be ustar").name[..name.len()].copy_from_slice(name);
    header.set_entry_type(EntryType::Regular);
    header.set_size(file.size);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    builder.get_mut().write_all(header.as_bytes())
}

fn append_data(
    out: &mut impl Write,
    file: &FileEntry,
    data: &mut impl Read,
) -> Result<(), PackError> {
    let mut buf = vec![0; COPY_SIZE];
    let mut remaining = file.size;
    while remaining > 0 {
        let chunk = &mut buf[..remaining.min(COPY_SIZE as u64) as usize];
        data.read_exact(chunk).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                PackError::SizeChanged(file.name.to_owned())
            } else {
                read_error(file, error)
            }
        })?;
        out.write_all(chunk)?;
        remaining -= chunk.len() as u64;
    }
    match data.read_exact(&mut [0]) {
        Ok(()) => return Err(PackError::SizeChanged(file.name.to_owned())),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(read_error(file, error)),
    }

    let padding = file.size.next_multiple_of(BLOCK_SIZE) - file.size;
    out.write_all(&[0; BLOCK_SIZE as usize][..padding as usize])?;
    Ok(())
}

fn read_error(file: &FileEntry, error: io::Error) -> PackError {
    PackError::Read {
        name: file.name.to_owned(),
        error,
    }
}

const FORBIDDEN_CHARS: [char; 8] = ['<', '>', ':', '\\', '/', '|', '?', '*'];
const RESERVED_NAMES: [&str; 28] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³",
];
const RIGHT_TO_LEFT_OVERRIDE: char = '\u{202E}';
const NONCHARACTERS: [char; 2] = ['\u{FFFE}', '\u{FFFF}'];
const MAX_NAME_LEN: usize = 1000;

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
// https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/ch03_container_format/#unencrypted-payload
fn is_valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with([' ', '-'])
        && !name.ends_with([' ', '.'])
        && !is_reserved_name(name)
        && !name.chars().any(|c| {
            FORBIDDEN_CHARS.contains(&c)
                || c.is_control()
                || c == RIGHT_TO_LEFT_OVERRIDE
                || NONCHARACTERS.contains(&c)
        })
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
