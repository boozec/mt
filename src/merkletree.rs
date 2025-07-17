//! Provides the MerkleTree structure and associated methods for creating and interacting
//! with binary Merkle trees using custom hashers.

use crate::{fs, hasher::Hasher, node::Node};
use rayon::prelude::*;

/// A binary Merkle tree implementation.
///
/// Merkle trees are hash-based data structures used for secure and efficient data verification.
/// Each leaf node contains the hash of a data item, and each internal node contains the hash
/// of the concatenation of its children's hashes.
pub struct MerkleTree {
    /// Leaf nodes at the base of the tree (may include a duplicate for even pairing).
    leaves: Vec<Node>,
    /// Height of the tree (number of levels including root).
    height: usize,
    /// Root node of the Merkle tree.
    root: Node,
}

impl MerkleTree {
    /// Creates a new `MerkleTree` from a collection of data items and a hash function.
    ///
    /// # Arguments
    ///
    /// * `hasher` - A reference to an implementation of the `Hasher` trait.
    /// * `data` - A vector of values to be converted into leaf nodes.
    ///
    /// # Panics
    ///
    /// Panics if the `data` vector is empty.
    ///
    /// # Notes
    ///
    /// If the number of leaf nodes is odd, the last node is duplicated to ensure all internal
    /// nodes have exactly two children.
    pub fn new<I, T, H>(hasher: H, data: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
        H: Hasher + 'static + std::marker::Sync,
    {
        let owned_data: Vec<T> = data.into_iter().collect();
        let data_slices: Vec<&[u8]> = owned_data.iter().map(|item| item.as_ref()).collect();

        assert!(
            !data_slices.is_empty(),
            "Merkle Tree requires at least one element"
        );

        let leaves: Vec<Node> = data_slices
            .iter()
            .map(|data| Node::new_leaf(hasher.hash(data)))
            .collect();

        Self::build(hasher, leaves)
    }

    /// Construct a Merkletree from an iter of String-s.
    pub fn from_paths<H>(hasher: H, paths: Vec<String>) -> Self
    where
        H: Hasher + 'static + std::marker::Sync + Clone,
    {
        let leaves = fs::hash_dir(hasher.clone(), paths);

        Self::build(hasher, leaves)
    }

    /// Constructs the internal nodes of the tree from the leaves upward and computes the root.
    fn build<H>(hasher: H, nodes: Vec<Node>) -> Self
    where
        H: Hasher + 'static + std::marker::Sync,
    {
        let leaves = nodes.clone();
        let mut current_level = nodes;
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        let mut height = 0;

        while current_level.len() > 1 {
            if current_level.len() % 2 != 0 {
                // duplicate last node to make the count even
                current_level.push(current_level.last().unwrap().clone());
            }

            next_level.clear();
            next_level = current_level
                .par_chunks(2)
                .map(|pair| {
                    let (left, right) = (&pair[0], &pair[1]);

                    let (left_hash, right_hash) = (left.hash().as_bytes(), right.hash().as_bytes());

                    let mut buffer = Vec::with_capacity(left_hash.len() + right_hash.len());
                    buffer.extend_from_slice(left_hash);
                    buffer.extend_from_slice(right_hash);

                    let hash = hasher.hash(&buffer);
                    Node::new_internal(hash, left.clone(), right.clone())
                })
                .collect();

            std::mem::swap(&mut current_level, &mut next_level);
            height += 1;
        }

        let root = current_level.remove(0);

        MerkleTree {
            leaves,
            height: height + 1,
            root,
        }
    }
    /// Returns the height (number of levels) of the tree.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns true if the tree has no leaves (should never happen if `new()` was used).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of leaf nodes in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the tree' leaves.
    pub fn leaves(&self) -> Vec<Node> {
        self.leaves.clone()
    }

    /// Returns the root node of the tree.
    pub fn root(&self) -> Node {
        self.root.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::*;

    #[test]
    fn test_merkle_tree_with_default_hasher() {
        let data = &["hello".as_bytes(), "world".as_bytes()];
        let tree = MerkleTree::new(DummyHasher, data);

        assert_eq!(tree.height(), 2);
        assert_eq!(tree.root().hash(), "hash_539");
    }

    #[test]
    fn test_merkle_tree_hashing() {
        let data = &["hello".as_bytes(), "world".as_bytes()];
        let tree = MerkleTree::new(SHA256Hasher::new(), data);

        assert_eq!(tree.height(), 2);
        assert_eq!(
            tree.root().hash(),
            "15e178b71fae8849ee562c9cc0d7ea322fba6cd495411329d47234479167cc8b"
        );
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let data = &["hello".as_bytes()];
        let tree = MerkleTree::new(SHA256Hasher::new(), data);

        assert_eq!(tree.height(), 1);
        assert_eq!(tree.len(), 1);
        assert_eq!(
            tree.root().hash(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_merkle_tree_with_10_elements() {
        let inputs = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
        let data: Vec<&[u8]> = inputs.iter().map(|s| s.as_bytes()).collect();

        let tree = MerkleTree::new(SHA256Hasher::new(), &data);

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
