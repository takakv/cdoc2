pub mod symmetric;

use symmetric::SymmetricKeyCapsule;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    Symmetric(SymmetricKeyCapsule),
    Unsupported,
}
