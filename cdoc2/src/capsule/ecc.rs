#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccPublicKeyCapsule {
    pub curve: EllipticCurve,
    pub recipient_public_key: Vec<u8>,
    pub sender_public_key: Vec<u8>,
}
