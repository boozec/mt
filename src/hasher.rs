//! Provides hashing abstractions and implementations including SHA256 and a default dummy hasher.

use sha2::{Digest, Sha256};
use sha3::Keccak512;

/// A trait representing a generic hash function.
///
/// This allows the Merkle tree to use any hash function that conforms to this interface.
pub trait Hasher {
    /// Hashes a sequence of bytes and returns the resulting hash as a hexadecimal string.
    fn hash(&self, input: &[u8]) -> String;
}

/// A dummy hasher used for testing or demonstration purposes.
///
/// Always returns a static hash value.
#[derive(Clone)]
pub struct DummyHasher;

impl Hasher for DummyHasher {
    fn hash(&self, input: &[u8]) -> String {
        let sum: u32 = input.iter().map(|&b| b as u32).sum();
        format!("hash_{:x}", sum)
    }
}

#[derive(Clone)]
/// A hasher implementation using the SHA-256 cryptographic hash function.
pub struct SHA256Hasher;

impl Default for SHA256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl SHA256Hasher {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hasher for SHA256Hasher {
    fn hash(&self, input: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }
}

#[derive(Clone)]
/// A hasher implementation using the Keccak512 cryptographic hash function.
pub struct Keccak512Hasher;

impl Default for Keccak512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Keccak512Hasher {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hasher for Keccak512Hasher {
    fn hash(&self, input: &[u8]) -> String {
        let mut hasher = Keccak512::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hasher_with_known_input() {
        let hasher = SHA256Hasher;
        let input = "hello".as_bytes();
        let expected_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_sha256_hasher_empty_string() {
        let hasher = SHA256Hasher;
        let input = &[];
        let expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_keccak512_hasher_with_known_input() {
        let hasher = Keccak512Hasher;
        let input = "hello".as_bytes();
        let expected_hash = "52fa80662e64c128f8389c9ea6c73d4c02368004bf4463491900d11aaadca39d47de1b01361f207c512cfa79f0f92c3395c67ff7928e3f5ce3e3c852b392f976";
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_keccak512_hasher_empty_string() {
        let hasher = Keccak512Hasher;
        let input = &[];
        let expected_hash = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e";
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }
}
