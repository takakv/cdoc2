use std::io;
use std::sync::Arc;

/// An I/O error that can be cloned and compared, so the error types holding it can be too.
/// Two are equal when their kind and message are.
#[derive(Debug, Clone, thiserror::Error)]
#[error(transparent)]
pub struct IoError(Arc<io::Error>);

impl IoError {
    pub fn kind(&self) -> io::ErrorKind {
        self.0.kind()
    }

    pub fn get_ref(&self) -> &io::Error {
        &self.0
    }
}

impl From<io::Error> for IoError {
    fn from(error: io::Error) -> Self {
        IoError(Arc::new(error))
    }
}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.kind() == other.kind() && self.0.to_string() == other.0.to_string()
    }
}

impl Eq for IoError {}
