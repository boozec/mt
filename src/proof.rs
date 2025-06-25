//! Merkle tree proof and verification implementation

use crate::{
    hasher::Hasher,
    node::{Node, NodeChildType},
};

/// Represents a single step in a Merkle proof path.
#[derive(Debug, Clone)]
pub struct ProofNode {
    /// The hash value of the sibling node.
    pub hash: String,
    /// Whether this sibling is left or right
    pub child_type: NodeChildType,
}

/// A Merkle proof containing the path from a leaf to the root.
#[derive(Debug)]
pub struct MerkleProof {
    /// The sequence of sibling hashes needed to reconstruct the path to root.
    pub path: Vec<ProofNode>,
    /// The index of the leaf node this proof corresponds.
    pub leaf_index: usize,
}

pub trait Proofer {
    /// Generates a Merkle proof for the data at the specified index
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the leaf node to generate a proof.
    ///
    /// # Returns
    ///
    /// `Some(MerkleProof)` if the index is valid, `None` otherwise.
    fn generate(&self, index: usize) -> Option<MerkleProof>;

    /// Verifies that a piece of data exists in the tree using a Merkle proof.
    ///
    /// # Arguments
    ///
    /// * `proof` - The Merkle proof.
    /// * `data` - The original data to verify.
    /// * `root_hash` - The expected root hash of the tree.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid and the data exists in the tree, `false` otherwise.
    fn verify<T>(&self, proof: &MerkleProof, data: T, root_hash: &str) -> bool
    where
        T: AsRef<[u8]>;
}

pub struct DefaultProofer<H: Hasher> {
    hasher: H,
    leaves: Vec<Node>,
}

impl<H> DefaultProofer<H>
where
    H: Hasher,
{
    pub fn new(hasher: H, leaves: Vec<Node>) -> Self {
        Self { hasher, leaves }
    }
}

impl<H> Proofer for DefaultProofer<H>
where
    H: Hasher,
{
    fn generate(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut path = Vec::new();
        let mut current_index = index;
        let mut current_level = self.leaves.clone();

        // Buildthe proof by walking up the tree
        while current_level.len() > 1 {
            // Ensure even number of nodes at this level
            if current_level.len() % 2 != 0 {
                current_level.push(current_level.last().unwrap().clone());
            }

            // Find the sibling of the current node
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1 // Right sibling
            } else {
                current_index - 1 // Left sibling
            };

            let child_type = if sibling_index < current_index {
                NodeChildType::Left
            } else {
                NodeChildType::Right
            };

            path.push(ProofNode {
                hash: current_level[sibling_index].hash().to_string(),
                child_type,
            });

            // Move to the next level
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2) {
                let (left, right) = (&pair[0], &pair[1]);

                let (left_hash, right_hash) = (left.hash().as_bytes(), right.hash().as_bytes());

                let mut buffer = Vec::<u8>::with_capacity(left_hash.len() + right_hash.len());
                buffer.extend_from_slice(left_hash);
                buffer.extend_from_slice(right_hash);

                let hash = self.hasher.hash(&buffer);
                next_level.push(Node::new_internal(hash, left.clone(), right.clone()));
            }
            current_level = next_level;
            current_index /= 2;
        }

        Some(MerkleProof {
            path,
            leaf_index: index,
        })
    }

    fn verify<T>(&self, proof: &MerkleProof, data: T, root_hash: &str) -> bool
    where
        T: AsRef<[u8]>,
    {
        // Start with the hash of the data
        let mut current_hash = self.hasher.hash(data.as_ref());

        // Walk up the tree using the proof path
        for proof_node in &proof.path {
            let combined: String = match proof_node.child_type {
                NodeChildType::Left => format!("{}{}", proof_node.hash, current_hash),
                NodeChildType::Right => format!("{}{}", current_hash, proof_node.hash),
            };
            current_hash = self.hasher.hash(combined.as_bytes());
        }

        // Check if the computed root matches the expected root
        current_hash == root_hash
    }
}

#[cfg(test)]
mod tests {
    use crate::{hasher::*, merkletree::MerkleTree};

    use super::*;

    #[test]
    fn test_proof_generation_and_verification_dummy() {
        let hasher = DummyHasher;
        let data = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::new(hasher.clone(), data.clone());
        let proofer = DefaultProofer::new(hasher, tree.leaves());

        for (index, item) in data.iter().enumerate() {
            let proof = proofer.generate(index).unwrap();

            assert!(proofer.verify(&proof, item, tree.root().hash()));
        }
    }

    #[test]
    fn test_proof_generation_and_verification_sha256() {
        let hasher = SHA256Hasher::new();
        let data = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::new(hasher.clone(), data.clone());
        let proofer = DefaultProofer::new(hasher, tree.leaves().clone());

        for (index, item) in data.iter().enumerate() {
            let proof = proofer.generate(index).unwrap();

            assert!(proofer.verify(&proof, item, tree.root().hash()));
        }
    }

    #[test]
    fn test_proof_not_valid() {
        let hasher = SHA256Hasher::new();
        let data = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::new(hasher.clone(), data.clone());
        let proofer = DefaultProofer::new(hasher, tree.leaves().clone());

        let proof = proofer.generate(0).unwrap();

        assert!(proofer.verify(&proof, b"a", tree.root().hash()));
        assert!(!proofer.verify(&proof, b"b", tree.root().hash()));
        assert!(!proofer.verify(&proof, b"c", tree.root().hash()));
        assert!(!proofer.verify(&proof, b"d", tree.root().hash()));

        assert!(!proofer.verify(&proof, b"e", tree.root().hash()));
    }
}
