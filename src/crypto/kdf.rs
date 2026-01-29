use argon2::{Algorithm, Argon2, Params, Version};
use crate::RencError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub fn password_default() -> Self {
        Self {
            mem_kib: 65_536,
            iterations: 3,
            parallelism: 4,
        }
    }

    pub fn pubkey_default() -> Self {
        Self {
            mem_kib: 1_024,
            iterations: 1,
            parallelism: 1,
        }
    }

    pub fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&self.mem_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.iterations.to_le_bytes());
        out[8..12].copy_from_slice(&self.parallelism.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        let mem_kib = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let iterations = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let parallelism = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        Self {
            mem_kib,
            iterations,
            parallelism,
        }
    }
}

pub fn derive_key(input: &[u8], salt: &[u8; 16], params: KdfParams) -> Result<[u8; 32], RencError> {
    let argon_params = Params::new(
        params.mem_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|err| RencError::Crypto(format!("Invalid KDF params: {err}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(input, salt, &mut output)
        .map_err(|err| RencError::Crypto(format!("KDF failed: {err}")))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_round_trip() {
        let params = KdfParams {
            mem_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let salt = [1u8; 16];
        let key1 = derive_key(b"password", &salt, params).expect("kdf");
        let key2 = derive_key(b"password", &salt, params).expect("kdf");
        assert_eq!(key1, key2);
    }
}
