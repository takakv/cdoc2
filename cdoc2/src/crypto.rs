pub const FMK_LEN: usize = 32;

pub(crate) type Hkdf = hkdf::Hkdf<sha2::Sha256>;
pub(crate) type Hmac = hmac::Hmac<sha2::Sha256>;
