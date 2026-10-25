use std::io;

use crate::IoError;

mod names;
mod pack;
mod unpack;

pub(crate) use names::check_file_names;
pub(crate) use pack::{PackError, pack};
pub(crate) use unpack::unpack;

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

impl<'a> From<&'a File> for FileEntry<'a> {
    fn from(file: &'a File) -> Self {
        FileEntry {
            name: &file.name,
            size: file.data.len() as u64,
        }
    }
}

pub trait Sink {
    fn create_file(&mut self, name: &str, size: u64) -> io::Result<()>;
    fn append(&mut self, data: &[u8]) -> io::Result<()>;
    fn finish_file(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink for Vec<File> {
    fn create_file(&mut self, name: &str, _size: u64) -> io::Result<()> {
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
    Write(IoError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileNameError {
    #[error("file name {0:?} is not allowed")]
    Unsafe(String),
    #[error("duplicate file name {0:?}")]
    Duplicate(String),
}

const BLOCK_SIZE: u64 = 512;

#[cfg(test)]
mod tests;
