//! Merkle tree proof and verification implementation

use crate::{
    hasher::Hasher,
    node::{Node, NodeChildType},
};
use rayon::prelude::*;

/// Represents a single step in a Merkle proof path.
#[derive(Debug, Clone)]
pub struct ProofNode {
    /// The hash value of the sibling node.
    pub hash: [u8; 32],
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
    fn verify<T>(&self, proof: &MerkleProof, data: T, root_hash: &[u8]) -> bool
    where
        T: AsRef<[u8]>;
}

pub struct DefaultProofer<H: Hasher> {
    hasher: H,
    levels: Vec<Vec<Node>>,
}

impl<H> DefaultProofer<H>
where
    H: Hasher,
{
    pub fn new(hasher: H, leaves: Vec<Node>) -> Self {
        let mut levels = Vec::new();
        levels.push(leaves.clone());

        let mut current_level = leaves;
        while current_level.len() > 1 {
            if current_level.len() % 2 != 0 {
                current_level.push(current_level.last().unwrap().clone());
            }
            let next_level: Vec<Node> = current_level
                .par_chunks(2)
                .map(|pair| {
                    let (left, right) = (&pair[0], &pair[1]);

                    let mut combined = Vec::with_capacity(64);
                    combined.extend_from_slice(left.hash());
                    combined.extend_from_slice(right.hash());
                    let hash = hasher.hash(&combined);
                    Node::new_internal(hash, left.clone(), right.clone())
                })
                .collect();

            levels.push(next_level.clone());
            current_level = next_level;
        }

        Self { hasher, levels }
    }

    pub fn verify_hash(&self, proof: &MerkleProof, hash: [u8; 32], root_hash: &[u8]) -> bool {
        let mut current_hash = hash;
        // Walk up the tree using the proof path
        for proof_node in &proof.path {
            let combined_array: [u8; 64] = match proof_node.child_type {
                NodeChildType::Left => {
                    let mut result = [0u8; 64];
                    result[..32].copy_from_slice(&proof_node.hash);
                    result[32..].copy_from_slice(&current_hash);
                    result
                }
                NodeChildType::Right => {
                    let mut result = [0u8; 64];
                    result[..32].copy_from_slice(&current_hash);
                    result[32..].copy_from_slice(&proof_node.hash);
                    result
                }
            };
            let combined: &[u8] = &combined_array;
            current_hash = self.hasher.hash(combined);
        }

        // Check if the computed root matches the expected root
        current_hash == root_hash
    }
}

impl<H> Proofer for DefaultProofer<H>
where
    H: Hasher,
{
    fn generate(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.levels[0].len() {
            return None;
        }

        let mut path = Vec::new();
        let mut current_index = index;

        for level in &self.levels[..self.levels.len() - 1] {
            // Flip the last bit and ensures that it never goes out-of-bounds
            let sibling_index = (current_index ^ 1).min(level.len() - 1);

            let sibling = &level[sibling_index];

            let child_type = if sibling_index < current_index {
                NodeChildType::Left
            } else {
                NodeChildType::Right
            };

            path.push(ProofNode {
                hash: *sibling.hash(),
                child_type,
            });

            current_index >>= 1;
        }

        Some(MerkleProof {
            path,
            leaf_index: index,
        })
    }

    fn verify<T>(&self, proof: &MerkleProof, data: T, root_hash: &[u8]) -> bool
    where
        T: AsRef<[u8]>,
    {
        // Start with the hash of the data
        let hash = self.hasher.hash(data.as_ref());
        self.verify_hash(proof, hash, root_hash)
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
