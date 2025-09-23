//! Provides hashing abstractions and implementations including SHA256 and a default dummy hasher.

use hex::FromHex;
use sha2::Digest;

/// A trait representing a generic hash function.
///
/// This allows the Merkle tree to use any hash function that conforms to this interface.
pub trait Hasher: Send + Sync {
    /// Hashes a sequence of bytes and returns the resulting hash as a hexadecimal string.
    fn hash(&self, input: &[u8]) -> [u8; 32];
}

/// A dummy hasher used for testing or demonstration purposes.
///
/// Always returns a static hash value.
#[derive(Clone, Default)]
pub struct DummyHasher;

impl Hasher for DummyHasher {
    fn hash(&self, input: &[u8]) -> [u8; 32] {
        let sum: u32 = input.iter().map(|&b| b as u32).sum();
        let bytes = Vec::<u8>::from_hex(format!("{:x}", sum)).unwrap_or_default();
        let mut hash_array: [u8; 32] = [0; 32];

        let len = bytes.len();
        hash_array[..len].copy_from_slice(&bytes);

        hash_array
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
    fn hash(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(input);

        hasher.finalize().into()
    }
}

#[derive(Clone)]
/// A hasher implementation using the Keccak256 cryptographic hash function.
pub struct Keccak256Hasher;

impl Default for Keccak256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Keccak256Hasher {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hasher for Keccak256Hasher {
    fn hash(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(input);
        hasher.finalize().into()
    }
}

#[derive(Clone)]
/// A hasher implementation using the Blake3 cryptographic hash function.
pub struct Blake3Hasher;

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3Hasher {
    pub fn new() -> Self {
        Self {}
    }
}

impl Hasher for Blake3Hasher {
    fn hash(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(input);
        hasher.finalize().into()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hasher_with_known_input() {
        let hasher = SHA256Hasher;
        let input = "hello".as_bytes();
        let expected_hash: [u8; 32] =
            Vec::<u8>::from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap()
                .try_into()
                .unwrap_or_default();

        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_sha256_hasher_empty_string() {
        let hasher = SHA256Hasher;
        let input = &[];
        let expected_hash: [u8; 32] =
            Vec::<u8>::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
                .try_into()
                .unwrap_or_default();
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_keccak256_hasher_with_known_input() {
        let hasher = Keccak256Hasher;
        let input = "hello".as_bytes();
        let expected_hash: [u8; 32] =
            Vec::<u8>::from_hex("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                .unwrap()
                .try_into()
                .unwrap_or_default();
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_keccak256_hasher_empty_string() {
        let hasher = Keccak256Hasher;
        let input = &[];
        let expected_hash: [u8; 32] =
            Vec::<u8>::from_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
                .try_into()
                .unwrap_or_default();
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_blake3_hasher_with_known_input() {
        let hasher = Blake3Hasher;
        let input = "hello".as_bytes();
        let expected_hash: [u8; 32] =
            Vec::<u8>::from_hex("ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f")
                .unwrap()
                .try_into()
                .unwrap_or_default();
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_blake3_hasher_empty_string() {
        let hasher = Blake3Hasher;
        let input = &[];
        let expected_hash: [u8; 32] =
            Vec::<u8>::from_hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
                .unwrap()
                .try_into()
                .unwrap_or_default();
        let actual_hash = hasher.hash(input);
        assert_eq!(actual_hash, expected_hash);
    }
}
