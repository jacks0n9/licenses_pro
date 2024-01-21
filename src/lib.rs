pub mod check {

    use crate::{generate_key_chunk, LicenseStructParameters, CHECKSUM_LEN, generate_checksum};
    pub struct LicenseCheckInfo<'a> {
        pub known_iv: &'a [u8],
        pub iv_index: usize,
    }
    pub struct License<'a> {
        pub seed: &'a[u8],
       pub  payload: Vec<Vec<u8>>,
      pub checksum: &'a [u8],
    }
    pub fn parse_license_bytes(
        license_bytes: &[u8],
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
            seed: &license_bytes[..params.seed_length],
            payload: chunks,
            checksum: &license_bytes[license_bytes.len() - CHECKSUM_LEN..],
        })
    }
    pub enum LicenseParseError {
        InvalidLength,
    }

    pub fn verify_license(license: License, info: LicenseCheckInfo) -> LicenseVerifyResult {
        if let Err(_) = license.verify_checksum() {
            return LicenseVerifyResult::ChecksumFailed;
        }
        let chunk_size = match license.payload.get(info.iv_index) {
            None => return LicenseVerifyResult::InvalidIVIndex,
            Some(t) => t,
        }
        .len();
        if license.payload[info.iv_index]
            == generate_key_chunk(info.known_iv, license.seed, chunk_size)
        {
            LicenseVerifyResult::LicenseGood
        } else {
            LicenseVerifyResult::LicenseBad
        }
    }
    impl License<'_> {
        pub fn verify_checksum(&self) -> Result<(), ()> {
            let checksum=generate_checksum(self.seed, self.payload.clone());
            if checksum == self.checksum {
                Ok(())
            } else {
                Err(())
            }
        }
    }
    pub enum LicenseVerifyResult {
        InvalidIVIndex,
        ChecksumFailed,
        LicenseGood,
        LicenseBad,
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
fn generate_checksum(seed: &[u8],payload: Vec<Vec<u8>>)->Vec<u8>{
    let mut context = digest::Context::new(&digest::SHA256);
    let to_verify = &vec![seed,&payload.concat()].concat();
    context.update(&to_verify);
    context.finish().as_ref()[..CHECKSUM_LEN].to_owned()
}
use ring::digest::{Context, SHA256, self};
fn generate_key_chunk<'a>(iv: &'a [u8], seed: &'a[u8], chunk_size: usize) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(&[iv, &seed].concat());
    let binding = context.finish();
    let hash = &binding.as_ref()[..chunk_size];
    hash.to_owned()
}
pub mod gen {
    use crate::{LicenseStructParameters, check::License, generate_key_chunk, generate_checksum};
    use rand::{self,rngs::OsRng, RngCore};

    pub struct AdminGenerator{
        pub parameters: LicenseStructParameters,
        pub ivs: Vec<Vec<u8>>
    }
    impl AdminGenerator{
        pub fn new_with_random_ivs(parameters: LicenseStructParameters)->Self{
            let mut chunks=vec![];
            for _ in 0..parameters.payload_length{
                let mut chunk=Vec::with_capacity(parameters.chunk_size);
                let mut rng=OsRng::default();
                rng.fill_bytes(&mut chunk);
                chunks.push(chunk);
            }
            Self{
                parameters,
                ivs: chunks

            }
        }
        pub fn generate_license<'a>(&'a self,seed: &'a [u8])->Result<License,LicenseGenError>{
            if seed.len()!=self.parameters.seed_length{
                return Err(LicenseGenError::InvalidSeedLen)
            }
            let mut payload=vec![];
            for iv in &self.ivs{
                payload.push(generate_key_chunk(&iv, seed, self.parameters.chunk_size));
            }
            Ok(License { seed, payload: payload.clone(), checksum: &generate_checksum(seed, payload) })
        }
    }
    enum LicenseGenError{
        InvalidSeedLen
    }
    impl License<'_>{
        fn to_bytes(&self)->Vec<u8>{
            [self.seed,&self.payload.concat(),self.checksum].concat()
        }
    }
    
}
