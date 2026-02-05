use std::io::Read;

use crate::RencError;
use crate::crypto::kdf::KdfParams;

/// Fixed header size in bytes.
pub const HEADER_SIZE: usize = 4 + 1 + 1 + 12 + 16 + 32 + 24;
/// Header size padded to the format's associated data block.
pub const HEADER_PADDED_SIZE: usize = 256;
/// Associated data size (padded header + u64 chunk index).
pub const AD_SIZE: usize = HEADER_PADDED_SIZE + 8;

const MAGIC: [u8; 4] = *b"RENC";
const VERSION: u8 = 0x01;

/// Encryption mode stored in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Password = 0x01,
    Pubkey = 0x02,
}

impl Mode {
    /// Parse a mode byte from the header.
    pub fn from_byte(value: u8) -> Result<Self, RencError> {
        match value {
            0x01 => Ok(Mode::Password),
            0x02 => Ok(Mode::Pubkey),
            other => Err(RencError::InvalidMode(other)),
        }
    }
}

/// Parsed header for the renc v1 format.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u8,
    pub mode: Mode,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 24],
}

impl Header {
    /// Build a header for password mode.
    pub fn new_password(kdf: KdfParams, salt: [u8; 16], nonce: [u8; 24]) -> Self {
        Self {
            version: VERSION,
            mode: Mode::Password,
            kdf,
            salt,
            ephemeral_pubkey: [0u8; 32],
            nonce,
        }
    }

    /// Build a header for public-key mode.
    pub fn new_pubkey(
        kdf: KdfParams,
        salt: [u8; 16],
        nonce: [u8; 24],
        ephemeral_pubkey: [u8; 32],
    ) -> Self {
        Self {
            version: VERSION,
            mode: Mode::Pubkey,
            kdf,
            salt,
            ephemeral_pubkey,
            nonce,
        }
    }

    /// Serialize the header to fixed-size bytes.
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = self.version;
        out[5] = self.mode as u8;
        out[6..18].copy_from_slice(&self.kdf.to_bytes());
        out[18..34].copy_from_slice(&self.salt);
        out[34..66].copy_from_slice(&self.ephemeral_pubkey);
        out[66..90].copy_from_slice(&self.nonce);
        out
    }

    /// Parse a header from fixed-size bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RencError> {
        if bytes.len() != HEADER_SIZE {
            return Err(RencError::InvalidHeader("Header size mismatch".to_string()));
        }
        if bytes[..4] != MAGIC {
            return Err(RencError::InvalidMagic);
        }
        let version = bytes[4];
        if version != VERSION {
            return Err(RencError::UnsupportedVersion(version));
        }
        let mode = Mode::from_byte(bytes[5])?;
        let mut kdf_bytes = [0u8; 12];
        kdf_bytes.copy_from_slice(&bytes[6..18]);
        let kdf = KdfParams::from_bytes(kdf_bytes);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[18..34]);
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&bytes[34..66]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[66..90]);
        Ok(Header {
            version,
            mode,
            kdf,
            salt,
            ephemeral_pubkey,
            nonce,
        })
    }

    /// Read and parse a header from a reader.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, RencError> {
        let mut buffer = [0u8; HEADER_SIZE];
        reader.read_exact(&mut buffer).map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                RencError::UnexpectedEof
            } else {
                RencError::Io(err.to_string())
            }
        })?;
        Header::from_bytes(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_constant() {
        assert_eq!(HEADER_SIZE, 90);
    }
}
