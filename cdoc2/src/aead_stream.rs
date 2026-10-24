use block_buffer::EagerBuffer;
use block_buffer::array::typenum::U16;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::{Block, Poly1305};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

const CHACHA20_BLOCK_LEN: u64 = 64;
const MAX_MESSAGE_LEN: u64 = (u32::MAX as u64 - 1) * CHACHA20_BLOCK_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadError {
    MessageTooLong,
    TagMismatch,
}

pub(crate) struct Encryptor(Core);

impl Encryptor {
    pub(crate) fn new(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8]) -> Self {
        Encryptor(Core::new(key, nonce, aad))
    }

    pub(crate) fn encrypt(&mut self, buf: &mut [u8]) -> Result<(), AeadError> {
        self.0.reserve(buf.len())?;
        self.0.cipher.apply_keystream(buf);
        self.0.authenticate(buf);
        Ok(())
    }

    pub(crate) fn finalize(self) -> [u8; TAG_LEN] {
        self.0.finish_mac().finalize().into()
    }
}

pub(crate) struct Decryptor(Core);

impl Decryptor {
    pub(crate) fn new(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8]) -> Self {
        Decryptor(Core::new(key, nonce, aad))
    }

    pub(crate) fn decrypt(&mut self, buf: &mut [u8]) -> Result<(), AeadError> {
        self.0.reserve(buf.len())?;
        self.0.authenticate(buf);
        self.0.cipher.apply_keystream(buf);
        Ok(())
    }

    pub(crate) fn verify(self, tag: &[u8; TAG_LEN]) -> Result<(), AeadError> {
        self.0
            .finish_mac()
            .verify(&Block::from(*tag))
            .map_err(|_| AeadError::TagMismatch)
    }
}

struct Core {
    cipher: ChaCha20,
    mac: Poly1305,
    pending: EagerBuffer<U16>,
    aad_len: u64,
    message_len: u64,
}

impl Core {
    fn new(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8]) -> Self {
        let mut cipher = ChaCha20::new(key.into(), nonce.into());

        // The Poly1305 key is the start of keystream block 0, and the message uses blocks 1 on.
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut mac_key);
        let mut mac = Poly1305::new(&mac_key);
        cipher.seek(CHACHA20_BLOCK_LEN);

        mac.update_padded(aad);
        Core {
            cipher,
            mac,
            pending: EagerBuffer::default(),
            aad_len: aad.len() as u64,
            message_len: 0,
        }
    }

    fn reserve(&mut self, len: usize) -> Result<(), AeadError> {
        let total = self.message_len + len as u64;
        if total > MAX_MESSAGE_LEN {
            return Err(AeadError::MessageTooLong);
        }
        self.message_len = total;
        Ok(())
    }

    fn authenticate(&mut self, data: &[u8]) {
        self.pending
            .digest_blocks(data, |blocks| self.mac.update(blocks));
    }

    fn finish_mac(mut self) -> Poly1305 {
        self.mac.update_padded(self.pending.get_data());

        let mut lengths = Block::default();
        lengths[..8].copy_from_slice(&self.aad_len.to_le_bytes());
        lengths[8..].copy_from_slice(&self.message_len.to_le_bytes());
        self.mac.update(&[lengths]);
        self.mac
    }
}

#[cfg(test)]
mod tests;
