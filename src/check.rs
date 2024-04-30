use crate::{
    blockers, generate_checksum, generate_key_chunk, LicenseStructParameters, CHECKSUM_LEN,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
use thiserror::Error;
/// Information needed for validating a license. If a keygen is made for your software, update this.
pub struct LicenseCheckInfo {
    pub known_iv: Vec<u8>,
    pub iv_index: usize,
}
/// Information contained within the license bytes.
#[derive(Clone)]
pub struct License {
    pub seed: Vec<u8>,
    pub payload: Vec<Vec<u8>>,
    pub checksum: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum LicenseParseError {
    #[error("invalid license length")]
    InvalidLength,
}
/// Check if a license is valid (checksum and key bytes).
/// A blocker is used to check if a license seed is blocked, but if you don't want it, set it to blockers::NoBlock.
pub fn verify_license<T: crate::blockers::Blocker>(
    license: License,
    info: LicenseCheckInfo,
    blocker: T,
) -> Result<(), LicenseVerifyError> {
    if license.verify_checksum().is_err() {
        return Err(LicenseVerifyError::ChecksumFailed);
    }
    let chunk_size = match license.payload.get(info.iv_index) {
        None => return Err(LicenseVerifyError::InvalidIVIndex),
        Some(t) => t,
    }
    .len();
    if license.payload[info.iv_index]
        == generate_key_chunk(&info.known_iv, &license.seed, chunk_size)
    {
        if let Err(e) = blocker.check_block(&license.seed) {
            return Err(LicenseVerifyError::LicenseBlocked(e));
        }
        Ok(())
    } else {
        Err(LicenseVerifyError::LicenseForged)
    }
}
impl License {
    /// Verifies only the checksum of your license, ignoring validity of key bytes.
    pub fn verify_checksum(&self) -> Result<(), WrongChecksum> {
        let checksum = generate_checksum(&self.seed, &self.payload);
        if checksum == self.checksum {
            Ok(())
        } else {
            Err(WrongChecksum)
        }
    }
    pub fn from_license_bytes(
        license_bytes: Vec<u8>,
        params: LicenseStructParameters,
    ) -> Result<License, LicenseParseError> {
        let payload_len_in_bytes = params.payload_length * params.chunk_size;
        let should_len = params.seed_length + payload_len_in_bytes + CHECKSUM_LEN;
        if license_bytes.len() != should_len {
            return Err(LicenseParseError::InvalidLength);
        }
        let og_payload = license_bytes
            [params.seed_length..params.seed_length + payload_len_in_bytes]
            .to_vec();
        let mut chunks = Vec::new();
        let mut i = 0;
        while i < og_payload.len() {
            chunks.push(og_payload[i..i + params.chunk_size].to_vec());
            i += params.chunk_size
        }
        Ok(License {
            seed: license_bytes[..params.seed_length].to_vec(),
            payload: chunks,
            checksum: license_bytes[license_bytes.len() - CHECKSUM_LEN..].to_vec(),
        })
    }
    pub fn from_human_readable(
        readable: String,
        params: LicenseStructParameters,
    ) -> Result<License, HumanReadableParseError> {
        let filtered: Vec<u8> = readable.bytes().filter(|x| *x != b'-').collect();
        let decoded = match base64engine.decode(filtered) {
            Ok(d) => d,
            Err(err) => return Err(HumanReadableParseError::Base64DecodeError(err)),
        };
        match Self::from_license_bytes(decoded, params) {
            Ok(p) => Ok(p),
            Err(err) => Err(HumanReadableParseError::ParseBytesError(err)),
        }
    }
}
#[derive(Debug)]

pub enum HumanReadableParseError {
    Base64DecodeError(base64::DecodeError),
    ParseBytesError(LicenseParseError),
}
#[derive(Debug, Error)]
#[error("checksum is invalid")]
pub struct WrongChecksum;
#[derive(Debug, PartialEq, Error)]
pub enum LicenseVerifyError {
    #[error("internal error: invalid iv inded")]
    InvalidIVIndex,
    #[error("checksum on license is invalid")]
    ChecksumFailed,
    #[error("license is forged")]
    LicenseForged,
    #[error("license has been blocked")]
    LicenseBlocked(blockers::BlockCheckError),
}
