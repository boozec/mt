//! Provides hashing abstractions and implementations including SHA256 and a default dummy hasher.

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

#[cfg(feature = "sha256")]
mod hasher_sha256 {
    use super::*;
    use sha2::{Digest, Sha256};

    #[derive(Clone)]
    /// A hasher implementation using the SHA-256 cryptographic hash function.
    pub struct SHA256Hasher;

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
    }
}

#[cfg(feature = "sha256")]
pub use hasher_sha256::*;
