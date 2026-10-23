pub const FMK_LEN: usize = 32;

pub(crate) type Hkdf = hkdf::Hkdf<sha2::Sha256>;
pub(crate) type Hmac = hmac::Hmac<sha2::Sha256>;

const FMK_INPUT_LEN: usize = 32;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn generate_fmk() -> Result<[u8; FMK_LEN], getrandom::Error> {
    let ikm = random_bytes::<FMK_INPUT_LEN>()?;
    let (fmk, _) = Hkdf::extract(Some(b"CDOC20salt"), &ikm);
    Ok(fmk.into())
}
