//! This crate allows you to verify and generate licenses.
//!
//! # Example usage
//! ```
//! use licenses_pro::gen::*;
//! use licenses_pro::LicenseStructParameters;
//! let generator=AdminGenerator::new_with_random_ivs(LicenseStructParameters::default());
//! // This generates a license with a seed, which should be constant length unique identifier.
//! // This example just uses some random bytes as a seed. The seed should be the same length as specified in the LicenseStructParameters
//! let license=generator.generate_license(vec![5, 100, 42, 69, 3,90]).unwrap();
//! println!("{}",license.to_human_readable()); // BWQq-RQNa-kDp6-mJn8-SSEh-UStw-p9+q-krw1-KDH4-mw
//! ```
//! Meanwhile on the client side
//! ```
//! use licenses_pro::check::*;
//! use licenses_pro::LicenseStructParameters;
//! let parsed=License::from_human_readable("BWQq-RQNa-kDp6-mJn8-SSEh-UStw-p9+q-krw1-KDH4-mw".to_string(),LicenseStructParameters::default()).unwrap();
//! let verify_result=verify_license(parsed,LicenseCheckInfo {
//!        known_iv: vec![43, 194, 247, 127, 168, 171, 16],
//!        iv_index: 0,
//!    },licenses_pro::blockers::NoBlock);
//! // Go ahead and match this!
//! ```
/// Check licenses generated by the generator
pub mod check {

    use crate::{
        blockers, generate_checksum, generate_key_chunk, LicenseStructParameters, CHECKSUM_LEN,
    };
    use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
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

    #[derive(Debug)]
    pub enum LicenseParseError {
        InvalidLength,
    }
    /// Check if a license is valid (checksum and key bytes).
    /// A blocker is used to check if a license seed is blocked, but if you don't want it, set it to blockers::NoBlock.
    pub fn verify_license<T: crate::blockers::Blocker>(
        license: License,
        info: LicenseCheckInfo,
        blocker: T,
    ) -> LicenseVerifyResult {
        if license.verify_checksum().is_err() {
            return LicenseVerifyResult::ChecksumFailed;
        }
        let chunk_size = match license.payload.get(info.iv_index) {
            None => return LicenseVerifyResult::InvalidIVIndex,
            Some(t) => t,
        }
        .len();
        if license.payload[info.iv_index]
            == generate_key_chunk(&info.known_iv, &license.seed, chunk_size)
        {
            if let Err(e) = blocker.check_block(&license.seed) {
                return LicenseVerifyResult::LicenseBlocked(e);
            }
            LicenseVerifyResult::LicenseGood
        } else {
            LicenseVerifyResult::LicenseForged
        }
    }
    impl License {
        /// Verifies only the checksum of your license, ignoring validity of key bytes.
        pub fn verify_checksum(&self) -> Result<(), ChecksumVerifyError> {
            let checksum = generate_checksum(&self.seed, &self.payload);
            if checksum == self.checksum {
                Ok(())
            } else {
                Err(ChecksumVerifyError::ChecksumDoesntMatch)
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
    #[derive(Debug)]
    pub enum ChecksumVerifyError {
        ChecksumDoesntMatch,
    }
    #[derive(Debug, PartialEq)]
    pub enum LicenseVerifyResult {
        InvalidIVIndex,
        ChecksumFailed,
        LicenseGood,
        LicenseForged,
        LicenseBlocked(blockers::BlockCheckError),
    }
}
/// Block compromised licenses
pub mod blockers {
    pub trait Blocker {
        fn check_block(&self, seed: &[u8]) -> Result<(), BlockCheckError>;
    }
    /// Blocker that always returns an Ok result
    pub struct NoBlock;
    impl Blocker for NoBlock {
        fn check_block(&self, _seed: &[u8]) -> Result<(), BlockCheckError> {
            Ok(())
        }
    }
    /// Blocks seeds hardcoded into the binary
    pub struct BuiltinBlocklist(Vec<Vec<u8>>);
    impl Blocker for BuiltinBlocklist {
        fn check_block(&self, seed: &[u8]) -> Result<(), BlockCheckError> {
            if self.0.contains(&seed.to_vec()) {
                Err(BlockCheckError::Blocked)
            } else {
                Ok(())
            }
        }
    }
    /// Fetch a remote page with a blocked base64-encoded seed on each line.
    /// This is nice because you don't actually have to host a server that validates licenses, you can just host this on pastebin or something.
    pub struct RemoteFileBlocker {
        pub url: reqwest::Url,
    }

    use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
    impl Blocker for RemoteFileBlocker {
        fn check_block(&self, seed: &[u8]) -> Result<(), BlockCheckError> {
            match reqwest::blocking::get(self.url.clone()) {
                Ok(response) => match response.error_for_status() {
                    Ok(response) => {
                        if let Ok(body) = response.bytes() {
                            let seeds_encoded = body.split(|x| *x == b'\n');
                            let mut seeds = vec![];
                            for seed in seeds_encoded {
                                if let Ok(b) = base64engine.decode(seed) {
                                    seeds.push(b);
                                } else {
                                    return Err(BlockCheckError::BadList);
                                }
                            }
                            if seeds.contains(&seed.to_vec()) {
                                return Err(BlockCheckError::Blocked);
                            }
                        } else {
                            return Err(BlockCheckError::BadList);
                        }
                    }
                    Err(_) => return Err(BlockCheckError::BadList),
                },
                Err(_) => return Err(BlockCheckError::BadList),
            }
            Ok(())
        }
    }
    #[derive(PartialEq, Debug)]

    pub enum BlockCheckError {
        BadList,
        Blocked,
    }
}
const CHECKSUM_LEN: usize = 2;

/// Information about the structure of your license.
/// This must be shared between your generator and checker.
pub struct LicenseStructParameters {
    // seed length in bytes
    pub seed_length: usize,

    // payload length in chunks
    pub payload_length: usize,
    // chunk size in bytes
    pub chunk_size: usize,
}

impl Default for LicenseStructParameters {
    fn default() -> Self {
        Self {
            seed_length: 6,
            payload_length: 10,
            chunk_size: 2,
        }
    }
}
fn generate_checksum(seed: &[u8], payload: &[Vec<u8>]) -> Vec<u8> {
    let mut context = digest::Context::new(&digest::SHA256);
    let to_verify = &[seed, &payload.concat()].concat();
    context.update(to_verify);
    context.finish().as_ref()[..CHECKSUM_LEN].to_owned()
}
use ring::digest::{self, Context, SHA256};
fn generate_key_chunk(iv: &[u8], seed: &Vec<u8>, chunk_size: usize) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(&[iv, &seed].concat());
    let binding = context.finish();
    let hash = &binding.as_ref()[..chunk_size];
    hash.to_owned()
}
/// Generate valid licenses
pub mod gen {
    use crate::{check::License, generate_checksum, generate_key_chunk, LicenseStructParameters};
    use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
    use rand::{self, rngs::OsRng, Rng, RngCore};
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
                let rng_len = rng.gen_range(1..10);
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
    #[derive(Debug)]
    pub enum LicenseGenError {
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
}
#[cfg(test)]
mod tests {
    use crate::check::{LicenseCheckInfo, LicenseVerifyResult};

    use self::{
        blockers::NoBlock,
        check::{verify_license, License},
        gen::AdminGenerator,
    };

    use super::*;
    #[test]
    fn checksum_works_for_valid() {
        new_test_license().verify_checksum().unwrap()
    }
    #[test]
    fn checksum_detects_invalid() {
        let mut license = new_test_license();
        license.payload[0][0] += 1;
        if let Ok(_) = license.verify_checksum() {
            panic!("Checksum should not be valid")
        }
    }
    #[test]
    fn license_works() {
        let genner = new_test_genner();
        let license = genner
            .generate_license(vec![5, 100, 42, 69, 3, 90])
            .unwrap();
        println!("{}", license.clone().to_human_readable());
        println!("{:?}", genner.ivs[0]);
        assert_eq!(
            verify_license(
                license,
                LicenseCheckInfo {
                    known_iv: genner.ivs[0].clone(),
                    iv_index: 0
                },
                NoBlock
            ),
            LicenseVerifyResult::LicenseGood
        );
    }
    #[test]
    fn forgery_detected() {
        let genner = new_test_genner();
        let license = genner
            .generate_license(vec![5, 100, 42, 69, 3, 90])
            .unwrap();
        if let LicenseVerifyResult::LicenseForged = verify_license(
            license,
            LicenseCheckInfo {
                known_iv: vec![182, 34],
                iv_index: 0,
            },
            NoBlock,
        ) {
        } else {
            panic!("Bad license detected as good")
        }
    }
    fn new_test_genner() -> AdminGenerator {
        let params = LicenseStructParameters {
            seed_length: 6,
            payload_length: 10,
            chunk_size: 2,
        };
        let genner = AdminGenerator::new_with_random_ivs(params);
        genner
    }
    fn new_test_license() -> License {
        let genner = new_test_genner();
        genner
            .generate_license(vec![5, 100, 42, 69, 3, 90])
            .unwrap()
    }
}
