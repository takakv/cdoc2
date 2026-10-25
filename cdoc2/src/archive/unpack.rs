use std::cell::Cell;
use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read, Take};

use flate2::bufread::ZlibDecoder;
use tar::EntryType;

use super::names::check_file_name;
use super::{BLOCK_SIZE, FileNameError, Sink, UnpackError};

pub(super) const MAX_ENTRY_HEADERS_SIZE: u64 = 64 * 1024;

pub(crate) fn unpack(
    compressed: impl Read,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), UnpackError> {
    let mut reader = ZlibDecoder::new(BufReader::new(compressed)).take(max_size.saturating_add(1));
    let result = unpack_limited(&mut reader, max_size, sink);
    if reader.limit() == 0 {
        return Err(UnpackError::TooLarge(max_size));
    }
    result
}

fn unpack_limited(
    reader: &mut Take<ZlibDecoder<impl BufRead>>,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), UnpackError> {
    let headers_budget = Cell::new(0);
    let limited = HeadersBudget {
        inner: &mut *reader,
        remaining: &headers_budget,
    };
    read_files(
        &mut tar::Archive::new(limited),
        &headers_budget,
        max_size,
        sink,
    )?;

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
    headers_budget: &Cell<u64>,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), UnpackError> {
    let mut names = HashSet::new();
    let mut total_size: u64 = 0;

    let mut entries = archive.entries().map_err(malformed)?;
    loop {
        headers_budget.set(MAX_ENTRY_HEADERS_SIZE);
        let Some(entry) = entries.next() else {
            break;
        };
        let mut entry = entry.map_err(malformed)?;
        headers_budget.set(u64::MAX);

        // tar skips PAX records it can't parse.
        if let Some(extensions) = entry.pax_extensions().map_err(malformed)? {
            for extension in extensions {
                extension.map_err(malformed)?;
            }
        }

        let path = entry.path_bytes().into_owned();
        let entry_type = entry.header().entry_type();
        if entry_type != EntryType::Regular {
            return Err(UnpackError::UnsupportedEntryType {
                name: String::from_utf8_lossy(&path).into_owned(),
                entry_type: char::from(entry_type.as_byte()),
            });
        }

        let name = String::from_utf8(path).map_err(|e| {
            FileNameError::Unsafe(String::from_utf8_lossy(e.as_bytes()).into_owned())
        })?;
        check_file_name(&name, &mut names)?;

        let size = entry.size();
        total_size = total_size.saturating_add(size);
        if total_size > max_size {
            return Err(UnpackError::TooLarge(max_size));
        }

        sink.create_file(&name, size).map_err(write_error)?;
        if copy_to_sink(&mut entry, sink)? != size {
            return Err(UnpackError::Malformed(format!("{name:?} is truncated")));
        }
        sink.finish_file().map_err(write_error)?;
    }

    Ok(())
}

struct HeadersBudget<'a, R> {
    inner: R,
    remaining: &'a Cell<u64>,
}

impl<R: Read> Read for HeadersBudget<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.remaining.get();
        if remaining == 0 && !buf.is_empty() {
            return Err(io::Error::other(format!(
                "entry headers exceed {MAX_ENTRY_HEADERS_SIZE} bytes"
            )));
        }
        let len = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..len])?;
        self.remaining.set(remaining - n as u64);
        Ok(n)
    }
}

fn copy_to_sink(entry: &mut impl Read, sink: &mut impl Sink) -> Result<u64, UnpackError> {
    let mut buf = [0; 8192];
    let mut copied = 0;
    loop {
        let n = entry.read(&mut buf).map_err(malformed)?;
        if n == 0 {
            return Ok(copied);
        }
        sink.append(&buf[..n]).map_err(write_error)?;
        copied += n as u64;
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
