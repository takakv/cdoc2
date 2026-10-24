pub mod password;
pub mod symmetric;

use password::Pbkdf2Capsule;
use symmetric::SymmetricKeyCapsule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    Symmetric(SymmetricKeyCapsule),
    Password(Pbkdf2Capsule),
    Unsupported,
}
