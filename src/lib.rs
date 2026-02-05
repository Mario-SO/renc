//! Rust Encryption Engine library for the renc CLI.
//!
//! This crate provides streaming encryption
//! and decryption with either a password (Argon2id) or recipient public key.
//! Use the `renc` binary for the CLI and JSON event output.

mod crypto;
mod format;
pub mod utils;

pub use crate::crypto::kdf::KdfParams;
pub use crate::format::header::{Header, Mode};

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Errors emitted by renc operations.
#[derive(Debug)]
pub enum RencError {
    Io(String),
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidMode(u8),
    PasswordRequired,
    SecretKeyRequired,
    AuthenticationFailed,
    InvalidEncryptedSize,
    UnexpectedEof,
    InvalidKey(String),
    InvalidHeader(String),
    InvalidArguments(String),
    Crypto(String),
}

impl RencError {
    pub fn code(&self) -> &'static str {
        match self {
            RencError::Io(_) => "Io",
            RencError::InvalidMagic => "InvalidMagic",
            RencError::UnsupportedVersion(_) => "UnsupportedVersion",
            RencError::InvalidMode(_) => "InvalidMode",
            RencError::PasswordRequired => "PasswordRequired",
            RencError::SecretKeyRequired => "SecretKeyRequired",
            RencError::AuthenticationFailed => "AuthenticationFailed",
            RencError::InvalidEncryptedSize => "InvalidEncryptedSize",
            RencError::UnexpectedEof => "UnexpectedEof",
            RencError::InvalidKey(_) => "InvalidKey",
            RencError::InvalidHeader(_) => "InvalidHeader",
            RencError::InvalidArguments(_) => "InvalidArguments",
            RencError::Crypto(_) => "Crypto",
        }
    }
}

impl std::fmt::Display for RencError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RencError::Io(err) => f.write_str(err),
            RencError::InvalidMagic => f.write_str("Invalid magic header"),
            RencError::UnsupportedVersion(v) => write!(f, "Unsupported version {v}"),
            RencError::InvalidMode(m) => write!(f, "Invalid mode {m}"),
            RencError::PasswordRequired => f.write_str("Password required"),
            RencError::SecretKeyRequired => f.write_str("Secret key required"),
            RencError::AuthenticationFailed => f.write_str("Authentication failed"),
            RencError::InvalidEncryptedSize => f.write_str("Invalid encrypted size"),
            RencError::UnexpectedEof => f.write_str("Unexpected end of file"),
            RencError::InvalidKey(err) => f.write_str(err),
            RencError::InvalidHeader(err) => f.write_str(err),
            RencError::InvalidArguments(err) => f.write_str(err),
            RencError::Crypto(err) => f.write_str(err),
        }
    }
}

impl std::error::Error for RencError {}

impl From<std::io::Error> for RencError {
    fn from(value: std::io::Error) -> Self {
        RencError::Io(value.to_string())
    }
}

pub struct Keypair {
    /// Base64-encoded Ed25519 public key (32 bytes).
    pub public_key_base64: String,
    /// Base64-encoded Ed25519 secret key seed (32 bytes).
    pub secret_key_base64: String,
}

/// Completion info for encrypt/decrypt operations.
pub struct DoneInfo {
    /// Output file path.
    pub output: PathBuf,
    /// Hex-encoded SHA-256 of the plaintext.
    pub hash_hex: String,
}

/// Generate a new Ed25519 keypair (base64-encoded) for public-key mode.
pub fn generate_keypair() -> Keypair {
    let (public, secret) = crypto::keys::generate_ed25519_keypair();
    Keypair {
        public_key_base64: crypto::keys::encode_base64(&public),
        secret_key_base64: crypto::keys::encode_base64(&secret),
    }
}

/// Read and parse the renc header from an encrypted file.
pub fn read_header_from_file(path: &Path) -> Result<Header, RencError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    Header::read_from(&mut reader)
}

/// Encrypt a file using a password-derived key (Argon2id).
pub fn encrypt_file_with_password(
    input: &Path,
    output: &Path,
    password: &[u8],
    mut progress: Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
) -> Result<DoneInfo, RencError> {
    let mut input_file = BufReader::new(File::open(input)?);
    let mut output_file = BufWriter::new(File::create(output)?);
    let total_size = input.metadata()?.len();

    let salt = crypto::keys::random_salt();
    let nonce = crypto::keys::random_nonce();
    let kdf = KdfParams::password_default();
    let mut key = crypto::kdf::derive_key(password, &salt, kdf)?;
    let header = Header::new_password(kdf, salt, nonce);

    output_file.write_all(&header.serialize())?;

    let hash_hex = format::stream::encrypt_stream(
        &mut input_file,
        &mut output_file,
        &header,
        &key,
        total_size,
        &mut progress,
    )?;

    key.zeroize();

    Ok(DoneInfo {
        output: output.to_path_buf(),
        hash_hex,
    })
}

/// Encrypt a file to a recipient Ed25519 public key (base64).
pub fn encrypt_file_with_pubkey(
    input: &Path,
    output: &Path,
    recipient_public_key_b64: &str,
    mut progress: Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
) -> Result<DoneInfo, RencError> {
    let mut input_file = BufReader::new(File::open(input)?);
    let mut output_file = BufWriter::new(File::create(output)?);
    let total_size = input.metadata()?.len();

    let recipient_public = crypto::keys::decode_base64_32(recipient_public_key_b64)?;
    let recipient_x25519 = crypto::keys::ed25519_public_to_x25519(&recipient_public)?;
    let (mut ephemeral_secret, ephemeral_public) = crypto::keys::generate_x25519_ephemeral();
    let mut shared_secret =
        crypto::keys::x25519_shared_secret(&ephemeral_secret, &recipient_x25519);

    let salt = crypto::keys::random_salt();
    let nonce = crypto::keys::random_nonce();
    let kdf = KdfParams::pubkey_default();
    let mut key = crypto::kdf::derive_key(&shared_secret, &salt, kdf)?;
    let header = Header::new_pubkey(kdf, salt, nonce, ephemeral_public);

    output_file.write_all(&header.serialize())?;

    let hash_hex = format::stream::encrypt_stream(
        &mut input_file,
        &mut output_file,
        &header,
        &key,
        total_size,
        &mut progress,
    )?;

    key.zeroize();
    shared_secret.zeroize();
    ephemeral_secret.zeroize();

    Ok(DoneInfo {
        output: output.to_path_buf(),
        hash_hex,
    })
}

/// Decrypt a password-mode file to the given output path.
pub fn decrypt_file_with_password(
    input: &Path,
    output: &Path,
    password: &[u8],
    mut progress: Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
) -> Result<DoneInfo, RencError> {
    let mut input_file = BufReader::new(File::open(input)?);
    let mut output_file = BufWriter::new(File::create(output)?);
    let encrypted_size = input.metadata()?.len();

    let header = Header::read_from(&mut input_file)?;
    if header.mode != Mode::Password {
        return Err(RencError::InvalidMode(header.mode as u8));
    }

    let mut key = crypto::kdf::derive_key(password, &header.salt, header.kdf)?;
    let hash_hex = format::stream::decrypt_stream(
        &mut input_file,
        &mut output_file,
        &header,
        &key,
        encrypted_size,
        &mut progress,
    )?;

    key.zeroize();

    Ok(DoneInfo {
        output: output.to_path_buf(),
        hash_hex,
    })
}

/// Decrypt a public-key mode file using the recipient secret key (base64).
pub fn decrypt_file_with_secret(
    input: &Path,
    output: &Path,
    secret_key_b64: &str,
    mut progress: Option<&mut dyn FnMut(u64, f64) -> Result<(), RencError>>,
) -> Result<DoneInfo, RencError> {
    let mut input_file = BufReader::new(File::open(input)?);
    let mut output_file = BufWriter::new(File::create(output)?);
    let encrypted_size = input.metadata()?.len();

    let header = Header::read_from(&mut input_file)?;
    if header.mode != Mode::Pubkey {
        return Err(RencError::InvalidMode(header.mode as u8));
    }

    let mut secret_seed = crypto::keys::decode_base64_32(secret_key_b64)?;
    let mut x25519_secret = crypto::keys::ed25519_secret_to_x25519(&secret_seed);
    let mut shared_secret =
        crypto::keys::x25519_shared_secret(&x25519_secret, &header.ephemeral_pubkey);

    let mut key = crypto::kdf::derive_key(&shared_secret, &header.salt, header.kdf)?;
    let hash_hex = format::stream::decrypt_stream(
        &mut input_file,
        &mut output_file,
        &header,
        &key,
        encrypted_size,
        &mut progress,
    )?;

    key.zeroize();
    shared_secret.zeroize();
    x25519_secret.zeroize();
    secret_seed.zeroize();

    Ok(DoneInfo {
        output: output.to_path_buf(),
        hash_hex,
    })
}

#[cfg(test)]
mod tests {
    use crate::crypto::kdf::KdfParams;
    use crate::format::header::{HEADER_SIZE, Header, Mode};

    #[test]
    fn header_round_trip() {
        let kdf = KdfParams {
            mem_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [7u8; 16];
        let nonce = [3u8; 24];
        let epk = [9u8; 32];
        let header = Header::new_pubkey(kdf, salt, nonce, epk);
        let bytes = header.serialize();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = Header::from_bytes(&bytes).expect("parse header");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.mode, Mode::Pubkey);
        assert_eq!(parsed.kdf.mem_kib, 1024);
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.ephemeral_pubkey, epk);
        assert_eq!(parsed.nonce, nonce);
    }
}
