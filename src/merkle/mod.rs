pub mod merkletree;
pub mod node;

#[cfg(test)]
mod tests {
    use crate::hasher::*;

    use super::*;

    #[test]
    fn test_merkle_tree_with_default_hasher() {
        let data = vec!["a", "b", "c", "d"];
        let tree = merkletree::MerkleTree::new(&DefaultHasher, data);

        assert_eq!(tree.height(), 3);

        assert_eq!(tree.root().hash(), "0xc0ff3");
    }

    #[test]
    #[cfg(feature = "sha256")]
    fn test_merkle_tree_hashing() {
        let data = vec!["a", "b", "c", "d"];
        let tree = merkletree::MerkleTree::new(&SHA256Hasher, data);

        assert_eq!(tree.height(), 3);

        assert_eq!(
            tree.root().hash(),
            "58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd"
        );
    }

    #[test]
    #[cfg(feature = "sha256")]
    fn test_merkle_tree_single_leaf() {
        let data = vec!["hello"];
        let tree = merkletree::MerkleTree::new(&SHA256Hasher, data);

        assert_eq!(tree.height(), 2);
        assert_eq!(tree.len(), 2);
        assert_eq!(
            tree.root().hash(),
            "286d189fda11bf4e906b6973a173009f47ede16532f1bae726223f8ee155d73b"
        );
    }
}
