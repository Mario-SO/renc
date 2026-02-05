use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use crate::RencError;
use crate::crypto::aead;
use crate::format::header::{AD_SIZE, HEADER_PADDED_SIZE, HEADER_SIZE, Header};

const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;

struct ProgressTracker {
    total: u64,
    next_emit: f64,
}

impl ProgressTracker {
    fn new(total: u64) -> Self {
        Self {
            total,
            next_emit: 5.0,
        }
    }

    fn emit_if_needed(
        &mut self,
        processed: u64,
        progress: &mut Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
    ) -> Result<(), RencError> {
        if self.total == 0 {
            if let Some(cb) = progress.as_deref_mut() {
                cb(processed, 100.0)?;
            }
            return Ok(());
        }
        let percent = (processed as f64 / self.total as f64) * 100.0;
        if percent + f64::EPSILON >= self.next_emit || percent >= 100.0 {
            if let Some(cb) = progress.as_deref_mut() {
                cb(processed, percent.min(100.0))?;
            }
            while self.next_emit <= percent {
                self.next_emit += 5.0;
            }
        }
        Ok(())
    }
}

fn padded_header_bytes(header: &Header) -> [u8; HEADER_PADDED_SIZE] {
    let mut padded = [0u8; HEADER_PADDED_SIZE];
    let bytes = header.serialize();
    padded[..HEADER_SIZE].copy_from_slice(&bytes);
    padded
}

fn derive_nonce(base: &[u8; 24], index: u64) -> [u8; 24] {
    let mut nonce = *base;
    let index_bytes = index.to_le_bytes();
    for (i, b) in index_bytes.iter().enumerate() {
        nonce[24 - 8 + i] ^= b;
    }
    nonce
}

fn build_ad(padded_header: &[u8; HEADER_PADDED_SIZE], index: u64) -> [u8; AD_SIZE] {
    let mut ad = [0u8; AD_SIZE];
    ad[..HEADER_PADDED_SIZE].copy_from_slice(padded_header);
    ad[HEADER_PADDED_SIZE..].copy_from_slice(&index.to_le_bytes());
    ad
}

/// Stream-encrypt reader to writer, returning plaintext SHA-256 hex.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &Header,
    key: &[u8; 32],
    total_plaintext: u64,
    progress: &mut Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
) -> Result<String, RencError> {
    let padded_header = padded_header_bytes(header);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut hasher = Sha256::new();
    let mut index = 0u64;
    let mut processed = 0u64;
    let mut tracker = ProgressTracker::new(total_plaintext);

    loop {
        let read_len = reader.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        let chunk = &mut buffer[..read_len];
        hasher.update(&chunk[..]);

        let nonce = derive_nonce(&header.nonce, index);
        let ad = build_ad(&padded_header, index);
        let tag = aead::encrypt_in_place(key, &nonce, &ad, chunk)?;

        writer.write_all(chunk)?;
        writer.write_all(&tag)?;

        processed += read_len as u64;
        tracker.emit_if_needed(processed, progress)?;
        index += 1;
    }

    tracker.emit_if_needed(processed, progress)?;
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Stream-decrypt reader to writer, returning plaintext SHA-256 hex.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &Header,
    key: &[u8; 32],
    encrypted_size: u64,
    progress: &mut Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
) -> Result<String, RencError> {
    if encrypted_size < HEADER_SIZE as u64 {
        return Err(RencError::InvalidEncryptedSize);
    }
    let payload_size = encrypted_size - HEADER_SIZE as u64;
    let total_plaintext = plaintext_size_from_payload(payload_size)?;

    let padded_header = padded_header_bytes(header);
    let mut hasher = Sha256::new();
    let mut index = 0u64;
    let mut processed = 0u64;
    let mut tracker = ProgressTracker::new(total_plaintext);

    let mut payload_remaining = payload_size;

    while payload_remaining > 0 {
        if payload_remaining < TAG_SIZE as u64 {
            return Err(RencError::InvalidEncryptedSize);
        }

        let chunk_len = if payload_remaining > (CHUNK_SIZE + TAG_SIZE) as u64 {
            CHUNK_SIZE as u64
        } else {
            payload_remaining - TAG_SIZE as u64
        };

        let mut buffer = vec![0u8; chunk_len as usize];
        reader
            .read_exact(&mut buffer)
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::UnexpectedEof => RencError::UnexpectedEof,
                _ => RencError::Io(err.to_string()),
            })?;
        let mut tag = [0u8; TAG_SIZE];
        reader
            .read_exact(&mut tag)
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::UnexpectedEof => RencError::UnexpectedEof,
                _ => RencError::Io(err.to_string()),
            })?;

        let nonce = derive_nonce(&header.nonce, index);
        let ad = build_ad(&padded_header, index);
        aead::decrypt_in_place(key, &nonce, &ad, &mut buffer, &tag)?;
        hasher.update(&buffer);
        writer.write_all(&buffer)?;

        processed += buffer.len() as u64;
        tracker.emit_if_needed(processed, progress)?;
        payload_remaining -= chunk_len + TAG_SIZE as u64;
        index += 1;
    }

    tracker.emit_if_needed(processed, progress)?;
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

fn plaintext_size_from_payload(payload_size: u64) -> Result<u64, RencError> {
    if payload_size == 0 {
        return Ok(0);
    }
    let full_chunk_size = (CHUNK_SIZE + TAG_SIZE) as u64;
    let full_chunks = payload_size / full_chunk_size;
    let remainder = payload_size % full_chunk_size;
    if remainder == 0 {
        return Ok(full_chunks * CHUNK_SIZE as u64);
    }
    if remainder < TAG_SIZE as u64 {
        return Err(RencError::InvalidEncryptedSize);
    }
    Ok(full_chunks * CHUNK_SIZE as u64 + (remainder - TAG_SIZE as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{KdfParams, derive_key};
    use std::io::Cursor;

    #[test]
    fn payload_size_to_plaintext_size() {
        let payload = (CHUNK_SIZE + TAG_SIZE) as u64 * 2 + 16;
        let plain = plaintext_size_from_payload(payload).expect("size");
        assert_eq!(plain, CHUNK_SIZE as u64 * 2);
    }

    #[test]
    fn encrypt_decrypt_round_trip_password() {
        let plaintext = b"hello renc".to_vec();
        let kdf = KdfParams {
            mem_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [7u8; 16];
        let nonce = [3u8; 24];
        let header = Header::new_password(kdf, salt, nonce);
        let key = derive_key(b"password", &salt, kdf).expect("kdf");

        let mut reader = Cursor::new(plaintext.clone());
        let mut encrypted = Cursor::new(Vec::new());
        let mut progress = None;
        let hash_enc = encrypt_stream(
            &mut reader,
            &mut encrypted,
            &header,
            &key,
            plaintext.len() as u64,
            &mut progress,
        )
        .expect("encrypt");

        let payload = encrypted.into_inner();
        let encrypted_size = HEADER_SIZE as u64 + payload.len() as u64;
        let mut payload_reader = Cursor::new(payload);
        let mut decrypted = Cursor::new(Vec::new());
        let mut progress = None;
        let hash_dec = decrypt_stream(
            &mut payload_reader,
            &mut decrypted,
            &header,
            &key,
            encrypted_size,
            &mut progress,
        )
        .expect("decrypt");

        assert_eq!(hash_enc, hash_dec);
        assert_eq!(decrypted.into_inner(), plaintext);
    }

    #[test]
    fn tamper_detection_fails() {
        let plaintext = b"tamper test".to_vec();
        let kdf = KdfParams {
            mem_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [5u8; 16];
        let nonce = [1u8; 24];
        let header = Header::new_password(kdf, salt, nonce);
        let key = derive_key(b"password", &salt, kdf).expect("kdf");

        let mut reader = Cursor::new(plaintext);
        let mut encrypted = Cursor::new(Vec::new());
        let mut progress = None;
        encrypt_stream(
            &mut reader,
            &mut encrypted,
            &header,
            &key,
            11,
            &mut progress,
        )
        .expect("encrypt");

        let mut payload = encrypted.into_inner();
        if !payload.is_empty() {
            payload[0] ^= 0xFF;
        }

        let encrypted_size = HEADER_SIZE as u64 + payload.len() as u64;
        let mut payload_reader = Cursor::new(payload);
        let mut decrypted = Cursor::new(Vec::new());
        let mut progress = None;
        let err = decrypt_stream(
            &mut payload_reader,
            &mut decrypted,
            &header,
            &key,
            encrypted_size,
            &mut progress,
        )
        .expect_err("should fail");
        assert_eq!(err.code(), "AuthenticationFailed");
    }
}
