use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::RencError;

pub fn generate_ed25519_keypair() -> Result<([u8; 32], [u8; 32]), RencError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let secret = signing_key.to_bytes();
    let public = signing_key.verifying_key().to_bytes();
    Ok((public, secret))
}

pub fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_base64_32(input: &str) -> Result<[u8; 32], RencError> {
    let bytes = STANDARD
        .decode(input.trim())
        .map_err(|err| RencError::InvalidKey(format!("Invalid base64: {err}")))?;
    if bytes.len() != 32 {
        return Err(RencError::InvalidKey(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn ed25519_public_to_x25519(public: &[u8; 32]) -> Result<[u8; 32], RencError> {
    let compressed = CompressedEdwardsY(*public);
    let edwards = compressed
        .decompress()
        .ok_or_else(|| RencError::InvalidKey("Invalid Ed25519 public key".to_string()))?;
    let montgomery = edwards.to_montgomery();
    Ok(montgomery.to_bytes())
}

pub fn ed25519_secret_to_x25519(secret_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(secret_seed);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

pub fn generate_x25519_ephemeral() -> Result<([u8; 32], [u8; 32]), RencError> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = X25519Secret::from(bytes);
    let public = X25519PublicKey::from(&secret);
    let secret_bytes = secret.to_bytes();
    bytes.zeroize();
    Ok((secret_bytes, public.to_bytes()))
}

pub fn x25519_shared_secret(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let secret = X25519Secret::from(*secret);
    let public = X25519PublicKey::from(*public);
    let shared = secret.diffie_hellman(&public);
    shared.to_bytes()
}

pub fn random_salt() -> Result<[u8; 16], RencError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

pub fn random_nonce() -> Result<[u8; 24], RencError> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_to_x25519_round_trip() {
        let (public, secret) = generate_ed25519_keypair().expect("keypair");
        let x25519_secret = ed25519_secret_to_x25519(&secret);
        let x25519_public = ed25519_public_to_x25519(&public).expect("public");
        let shared1 = x25519_shared_secret(&x25519_secret, &x25519_public);
        let shared2 = x25519_shared_secret(&x25519_secret, &x25519_public);
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn shared_secret_matches_between_peers() {
        let (recipient_public, recipient_secret) = generate_ed25519_keypair().expect("keys");
        let recipient_x_public =
            ed25519_public_to_x25519(&recipient_public).expect("recipient public");
        let recipient_x_secret = ed25519_secret_to_x25519(&recipient_secret);
        let (ephemeral_secret, ephemeral_public) = generate_x25519_ephemeral().expect("ephemeral");

        let shared_sender = x25519_shared_secret(&ephemeral_secret, &recipient_x_public);
        let shared_receiver = x25519_shared_secret(&recipient_x_secret, &ephemeral_public);

        assert_eq!(shared_sender, shared_receiver);
    }
}
