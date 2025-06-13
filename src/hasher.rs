use sha2::{Digest, Sha256};

pub trait Hasher {
    fn hash(&self, input: &str) -> String;
}

pub struct DefaultHasher;

impl Hasher for DefaultHasher {
    fn hash(&self, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_hasher_with_known_input() {
        let hasher = DefaultHasher;
        let input = "hello";
        let expected_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        let actual_hash = hasher.hash(input);

        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_default_hasher_empty_string() {
        let hasher = DefaultHasher;
        let input = "";
        let expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let actual_hash = hasher.hash(input);

        assert_eq!(actual_hash, expected_hash);
    }
}
