use thiserror::Error;
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
#[cfg(feature = "reqwest")]
/// Fetch a remote page with a blocked base64-encoded seed on each line.
/// This is nice because you don't actually have to host a server that validates licenses, you can just host this on pastebin or something.
pub struct RemoteFileBlocker {
    pub url: reqwest::Url,
}
#[cfg(feature = "reqwest")]
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64engine, Engine};
#[cfg(feature = "reqwest")]

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
#[derive(PartialEq, Debug, Error)]

pub enum BlockCheckError {
    #[error("list provided is invalid")]
    BadList,
    #[error("license is blocked")]
    Blocked,
}
