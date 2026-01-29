use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};

use crate::RencError;

/// Encrypt data in-place and return the detached tag.
pub fn encrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; 16], RencError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buffer)
        .map_err(|_| RencError::Crypto("AEAD encrypt failed".to_string()))?;
    Ok(tag.into())
}

/// Decrypt data in-place using a detached tag.
pub fn decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), RencError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = Tag::from(*tag);
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, buffer, &tag)
        .map_err(|_| RencError::AuthenticationFailed)
}
