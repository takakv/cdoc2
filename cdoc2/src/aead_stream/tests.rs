use std::ops::Range;

use wycheproof::TestResult;
use wycheproof::aead::{TestName, TestSet};

use super::*;

const CHUNKINGS: &[&[usize]] = &[&[usize::MAX], &[1], &[0, 1, 15, 16, 17, 63, 64, 65]];

fn chunk_ranges(len: usize, chunking: &[usize]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for &size in chunking.iter().cycle() {
        let end = start + size.min(len - start);
        ranges.push(start..end);
        start = end;
        if start == len {
            break;
        }
    }
    ranges
}

fn encrypt_in_chunks(mut encryptor: Encryptor, msg: &[u8], chunking: &[usize]) -> Vec<u8> {
    let mut buf = msg.to_vec();
    for range in chunk_ranges(buf.len(), chunking) {
        encryptor.encrypt(&mut buf[range]).unwrap();
    }
    buf.extend(encryptor.finalize());
    buf
}

fn decrypt_in_chunks(
    mut decryptor: Decryptor,
    encrypted: &[u8],
    chunking: &[usize],
) -> Result<Vec<u8>, AeadError> {
    let (ciphertext, tag) = encrypted.split_last_chunk::<TAG_LEN>().unwrap();
    let mut buf = ciphertext.to_vec();
    for range in chunk_ranges(buf.len(), chunking) {
        decryptor.decrypt(&mut buf[range]).unwrap();
    }
    decryptor.verify(tag)?;
    Ok(buf)
}

#[test]
fn wycheproof() {
    let set = TestSet::load(TestName::ChaCha20Poly1305).unwrap();
    let cases: Vec<_> = set
        .test_groups
        .iter()
        .filter(|group| group.nonce_size == 96)
        .flat_map(|group| &group.tests)
        .collect();
    assert_eq!(cases.len(), 316);

    for case in cases {
        let key = case.key.as_slice().try_into().unwrap();
        let nonce = case.nonce.as_slice().try_into().unwrap();
        let encrypted = [case.ct.as_slice(), &case.tag].concat();

        for chunking in CHUNKINGS {
            let context = format!("case {}, chunks {chunking:?}", case.tc_id);
            let decryptor = Decryptor::new(&key, &nonce, &case.aad);
            let decrypted = decrypt_in_chunks(decryptor, &encrypted, chunking);

            if case.result == TestResult::Valid {
                let encryptor = Encryptor::new(&key, &nonce, &case.aad);
                let reencrypted = encrypt_in_chunks(encryptor, &case.pt, chunking);
                assert_eq!(reencrypted, encrypted, "{context}");
                assert_eq!(decrypted, Ok(case.pt.to_vec()), "{context}");
            } else {
                assert_eq!(decrypted, Err(AeadError::TagMismatch), "{context}");
            }
        }
    }
}

#[test]
fn message_length_limit() {
    let skip_to_last_block = |core: &mut Core| {
        core.cipher.seek(MAX_MESSAGE_LEN);
        core.message_len = MAX_MESSAGE_LEN - CHACHA20_BLOCK_LEN;
    };

    let mut encryptor = Encryptor::new(&[0; KEY_LEN], &[0; NONCE_LEN], &[]);
    skip_to_last_block(&mut encryptor.0);
    assert_eq!(encryptor.encrypt(&mut [0; 64]), Ok(()));
    assert_eq!(
        encryptor.encrypt(&mut [0; 1]),
        Err(AeadError::MessageTooLong)
    );

    let mut decryptor = Decryptor::new(&[0; KEY_LEN], &[0; NONCE_LEN], &[]);
    skip_to_last_block(&mut decryptor.0);
    let mut buf = [1; 65];
    assert_eq!(decryptor.decrypt(&mut buf), Err(AeadError::MessageTooLong));
    assert_eq!(buf, [1; 65]);
    assert_eq!(decryptor.decrypt(&mut buf[..64]), Ok(()));
}
