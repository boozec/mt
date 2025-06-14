//! Provides the MerkleTree structure and associated methods for creating and interacting
//! with binary Merkle trees using custom hashers.

use crate::{hasher::Hasher, merkle::node::Node};

/// A binary Merkle tree implementation.
///
/// Merkle trees are hash-based data structures used for secure and efficient data verification.
/// Each leaf node contains the hash of a data item, and each internal node contains the hash
/// of the concatenation of its children's hashes.
#[derive(Debug)]
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
    pub fn new<T: ToString>(hasher: &dyn Hasher, data: Vec<T>) -> Self {
        assert!(
            !data.is_empty(),
            "Merkle Tree requires at least one element"
        );

        let mut leaves: Vec<Node> = data
            .into_iter()
            .map(|x| Node::new_leaf(hasher, x))
            .collect();

        if leaves.len() % 2 != 0 {
            leaves.push(leaves[leaves.len() - 1].clone());
        }

        Self::build(hasher, leaves)
    }

    /// Constructs the internal nodes of the tree from the leaves upward and computes the root.
    fn build(hasher: &dyn Hasher, mut nodes: Vec<Node>) -> Self {
        let leaves = nodes.clone();
        let mut height = 0;

        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for pair in nodes.chunks(2) {
                let (left, right) = (pair[0].clone(), pair[1].clone());
                next_level.push(Node::new_internal(hasher, left, right));
            }
            nodes = next_level;
            height += 1;
        }

        let root = nodes.remove(0);

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

    /// Returns the root node of the tree.
    pub fn root(&self) -> Node {
        self.root.clone()
    }
}
