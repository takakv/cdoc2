//! CDOC2 encrypted document containers.

mod aead_stream;
pub mod archive;
pub mod capsule;
#[cfg(feature = "x509")]
pub mod certificate;
pub mod container;
mod crypto;
pub mod decrypt;
pub mod encrypt;
#[cfg(feature = "hazmat")]
pub mod hazmat;
pub mod header;
mod io_error;
pub mod key_label;
pub mod payload;

pub use io_error::IoError;
