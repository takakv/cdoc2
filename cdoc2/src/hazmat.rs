//! Faster functions that are easy to misuse. Requires the `hazmat` feature.

use std::io::{Read, Seek};

use crate::archive::Sink;
use crate::container::ContainerHead;
use crate::decrypt::{DecryptError, DecryptionKey, authenticate, decrypt_payload};
use crate::header::RecipientRecord;

/// Like [`decrypt_into`](crate::decrypt::decrypt_into), but reads `payload` only once and checks
/// the tag at the end. The sink receives the files before they are authenticated, so its contents
/// may be forged unless this returns `Ok`.
pub fn decrypt_into_unverified(
    head: &ContainerHead,
    record: &RecipientRecord,
    key: &DecryptionKey,
    payload: impl Read + Seek,
    max_size: u64,
    sink: &mut impl Sink,
) -> Result<(), DecryptError> {
    let header = authenticate(head, record, key)?;
    decrypt_payload(&header, payload, max_size, sink)
}
