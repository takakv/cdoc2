use std::io::{self, Read, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use tar::{EntryType, Header};

use super::{BLOCK_SIZE, FileEntry};

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
