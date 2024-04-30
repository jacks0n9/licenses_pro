use crate::{check::License, generate_checksum, generate_key_chunk, LicenseStructParameters};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
use rand::{self, rngs::OsRng, Rng, RngCore};
use thiserror::Error;
/// For a piece of software, the admin generator should be created and stored once
pub struct AdminGenerator {
    pub parameters: LicenseStructParameters,
    pub ivs: Vec<Vec<u8>>,
}
impl AdminGenerator {
    /// Creates a new admin generator with your parameters using initialization vectors (IVs)
    pub fn new_with_random_ivs(parameters: LicenseStructParameters) -> Self {
        let mut ivs = vec![];
        for _ in 0..parameters.payload_length {
            let mut rng = OsRng;
            // Arbitrary range
            let rng_len = rng.gen_range(10..16);
            let mut iv = vec![];
            for _ in 0..rng_len {
                let mut single = [0u8; 1];
                rng.fill_bytes(&mut single);
                iv.push(single[0]);
            }
            rng.fill_bytes(&mut iv);
            ivs.push(iv);
        }
        Self { parameters, ivs }
    }
    /// Create a new valid license
    pub fn generate_license(&self, seed: Vec<u8>) -> Result<License, LicenseGenError> {
        if seed.len() != self.parameters.seed_length {
            return Err(LicenseGenError::InvalidSeedLen);
        }
        let mut payload = vec![];
        for iv in &self.ivs {
            payload.push(generate_key_chunk(iv, &seed, self.parameters.chunk_size));
        }
        let checksum = generate_checksum(&seed, &payload);
        Ok(License {
            seed,
            payload,
            checksum,
        })
    }
}
#[derive(Debug, Error)]
pub enum LicenseGenError {
    #[error("seed length is invalid")]
    InvalidSeedLen,
}
impl License {
    pub fn to_bytes(self) -> Vec<u8> {
        [self.seed, self.payload.concat(), self.checksum].concat()
    }
}
impl License {
    /// Base64 encode your license and seperate it with dashes
    pub fn to_human_readable(self) -> String {
        let binding = base64engine.encode(self.to_bytes());
        let encoded = binding.bytes();
        let mut dashed = "".to_string();
        for (i, character) in encoded.enumerate() {
            if i % 4 == 0 && i != 0 {
                dashed += "-"
            }
            dashed.push(character.into());
        }
        dashed
    }
}
