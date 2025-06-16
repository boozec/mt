//! High-level module for Merkle tree functionality.
//!
//! Re-exports the Merkle tree and node modules for external use.

pub mod merkletree;
pub mod node;

#[cfg(test)]
mod tests {
    use crate::hasher::*;

    use super::*;

    #[test]
    fn test_merkle_tree_with_default_hasher() {
        let data = &["hello".as_bytes(), "world".as_bytes()];
        let tree = merkletree::MerkleTree::new(&DefaultHasher, data);

        assert_eq!(tree.height(), 2);
        assert_eq!(tree.root().hash(), "0xc0ff3");
    }

    #[test]
    #[cfg(feature = "sha256")]
    fn test_merkle_tree_hashing() {
        let data = &["hello".as_bytes(), "world".as_bytes()];
        let tree = merkletree::MerkleTree::new(&SHA256Hasher, data);

        assert_eq!(tree.height(), 2);
        assert_eq!(
            tree.root().hash(),
            "15e178b71fae8849ee562c9cc0d7ea322fba6cd495411329d47234479167cc8b"
        );
    }

    #[test]
    #[cfg(feature = "sha256")]
    fn test_merkle_tree_single_leaf() {
        let data = &["hello".as_bytes()];
        let tree = merkletree::MerkleTree::new(&SHA256Hasher, data);

        assert_eq!(tree.height(), 2);
        assert_eq!(tree.len(), 2);
        assert_eq!(
            tree.root().hash(),
            "286d189fda11bf4e906b6973a173009f47ede16532f1bae726223f8ee155d73b"
        );
    }

    #[test]
    #[cfg(feature = "sha256")]
    fn test_merkle_tree_with_10_elements() {
        let inputs = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
        let data: Vec<&[u8]> = inputs.iter().map(|s| s.as_bytes()).collect();

        let tree = merkletree::MerkleTree::new(&SHA256Hasher, &data);

        assert_eq!(tree.height(), 5); // 10 elements padded to 16 → log2(16) + 1 = 5

        // You can print the root hash if you're unsure what it should be:
        println!("Merkle root hash: {}", tree.root().hash());

        // If you know the expected hash, use:
        assert_eq!(
            tree.root().hash(),
            "9da1ff0dfa79217bdbea9ec96407b1e693646cc493f64059fa27182a37cadf94"
        );
    }
}
