use std::io;
use std::sync::Arc;

/// A wrapper around an [`io::Error`].
#[derive(Debug, Clone, thiserror::Error)]
#[error(transparent)]
pub struct IoError(Arc<io::Error>);

impl IoError {
    /// Returns the error's kind.
    pub fn kind(&self) -> io::ErrorKind {
        self.0.kind()
    }

    /// Returns the original I/O error.
    pub fn get_ref(&self) -> &io::Error {
        &self.0
    }
}

impl From<io::Error> for IoError {
    fn from(error: io::Error) -> Self {
        IoError(Arc::new(error))
    }
}

/// Two `IoError`s are equal if their kinds and messages are.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind() == other.kind() && self.0.to_string() == other.0.to_string()
    }
}

impl Eq for IoError {}
