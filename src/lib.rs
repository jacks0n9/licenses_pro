pub mod check {

    use crate::{generate_checksum, generate_key_chunk, LicenseStructParameters, CHECKSUM_LEN};
    pub struct LicenseCheckInfo {
        pub known_iv: Vec<u8>,
        pub iv_index: usize,
    }
    pub struct License {
        pub seed: Vec<u8>,
        pub payload: Vec<Vec<u8>>,
        pub checksum: Vec<u8>,
    }
    pub fn parse_license_bytes(
        license_bytes: Vec<u8>,
        params: LicenseStructParameters,
    ) -> Result<License, LicenseParseError> {
        let payload_len_in_bytes = params.payload_length * params.chunk_size;
        let should_len = params.seed_length + payload_len_in_bytes + CHECKSUM_LEN;
        if license_bytes.len() != should_len {
            return Err(LicenseParseError::InvalidLength);
        }
        let og_payload =
            license_bytes[params.seed_length..params.seed_length + payload_len_in_bytes].to_vec();
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
    #[derive(Debug)]
    pub enum LicenseParseError {
        InvalidLength,
    }

    pub fn verify_license(license: License, info: LicenseCheckInfo) -> LicenseVerifyResult {
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
            LicenseVerifyResult::LicenseGood
        } else {
            LicenseVerifyResult::LicenseBad
        }
    }
    impl License {
        pub fn verify_checksum(&self) -> Result<(), ChecksumVerifyError> {
            let checksum = generate_checksum(&self.seed, &self.payload);
            if checksum == self.checksum {
                Ok(())
            } else {
                Err(ChecksumVerifyError::ChecksumDoesntMatch)
            }
        }
    }
    #[derive(Debug)]
    pub enum ChecksumVerifyError{
        ChecksumDoesntMatch
    }
    #[derive(Debug)]
    #[derive(PartialEq)]
    pub enum LicenseVerifyResult {
        InvalidIVIndex,
        ChecksumFailed,
        LicenseGood,
        LicenseBad,
    }
}
pub mod blockers{
    trait Blocker{
        fn check_block(&self,seed: &[u8])->Result<(),BlockCheckError>;
    }
    /// Blocks seeds hardcoded into the binary
    pub struct BuiltinBlocklist(Vec<Vec<u8>>);
    impl Blocker for BuiltinBlocklist{
        fn check_block(&self,seed: &[u8])->Result<(),BlockCheckError> {
            if self.0.contains(&seed.to_vec()){
                Err(BlockCheckError::Blocked)
            }else{
                Ok(())
            }
        }
    }
    /// Fetch a remote page with a blocked base64-encoded seed on each line.
    /// This is nice because you don't actually have to host a server that validates licenses, you can just host this on pastebin or something.
    pub struct RemoteFileBlocker{
        pub url: reqwest::Url
    }
    use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
    impl Blocker for RemoteFileBlocker{
        fn check_block(&self,seed: &[u8])->Result<(),BlockCheckError> {
            match reqwest::blocking::get(self.url.clone()){
                Ok(response) => match response.error_for_status(){
                    Ok(response) => {
                        if let Ok(body)=response.bytes(){
                            let seeds_encoded=body.split(|x|*x==b'\n');
                            let mut seeds=vec![];
                            for seed in seeds_encoded{
                                if let Ok(b)=base64engine.decode(seed){
                                    seeds.push(b);
                                }else{
                                    return Err(BlockCheckError::BadList)
                                }
                            }
                            if seeds.contains(&seed.to_vec()){
                                return Err(BlockCheckError::Blocked)
                            }
                        }else{
                            return Err(BlockCheckError::BadList)
                        }
                    },
                    Err(_) => return Err(BlockCheckError::BadList),
                },
                Err(_) => return Err(BlockCheckError::BadList),
            }
            Ok(())
        }
    }
    pub enum BlockCheckError{
        BadList,
        Blocked
    }
}
const CHECKSUM_LEN: usize = 2;

// Make sure these are configured the same way on the generator!!!
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
pub mod gen {
    use crate::{check::License, generate_checksum, generate_key_chunk, LicenseStructParameters};
    use rand::{self, rngs::OsRng, RngCore};

    pub struct AdminGenerator {
        pub parameters: LicenseStructParameters,
        pub ivs: Vec<Vec<u8>>,
    }
    impl AdminGenerator {
        pub fn new_with_random_ivs(parameters: LicenseStructParameters) -> Self {
            let mut chunks = vec![];
            for _ in 0..parameters.payload_length {
                let mut chunk = Vec::with_capacity(parameters.chunk_size);
                let mut rng = OsRng;
                rng.fill_bytes(&mut chunk);
                chunks.push(chunk);
            }
            Self {
                parameters,
                ivs: chunks,
            }
        }
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
   
}
#[cfg(test)]
mod tests {
    use crate::check::{LicenseCheckInfo, LicenseVerifyResult};

    use self::{
        check::{verify_license, License},
        gen::AdminGenerator,
    };

    use super::*;
    #[test]
    fn checksum_works_for_valid() {
        new_test_license().verify_checksum().unwrap()
    }
    #[test]
    fn checksum_detects_invalid(){
        let mut license=new_test_license();
        license.payload[0][0]+=1;
        if let Ok(_)=license.verify_checksum(){
            panic!("Checksum should not be valid")
        }
    }
    #[test]
    fn license_works() {
        let genner = new_test_genner();
        let license = genner.generate_license(vec![5, 100, 42, 69, 3]).unwrap();
        assert_eq!(
            verify_license(
                license,
                LicenseCheckInfo {
                    known_iv: genner.ivs[0].clone(),
                    iv_index: 0
                }
            ),
            LicenseVerifyResult::LicenseGood
        );
    }
    #[test]
    fn forgery_detected() {
        let genner = new_test_genner();
        let license = genner.generate_license(vec![5, 100, 42, 69, 3]).unwrap();
        if let LicenseVerifyResult::LicenseBad = verify_license(
            license,
            LicenseCheckInfo {
                known_iv: vec![182, 34],
                iv_index: 0,
            },
        ) {
        } else {
            panic!("Bad license detected as good")
        }
    }
    fn new_test_genner() -> AdminGenerator {
        let params = LicenseStructParameters {
            seed_length: 5,
            payload_length: 10,
            chunk_size: 2,
        };
        let genner = AdminGenerator::new_with_random_ivs(params);
        genner
    }
    fn new_test_license() -> License {
        let genner = new_test_genner();
        genner.generate_license(vec![5, 100, 42, 69, 3]).unwrap()
    }
}
