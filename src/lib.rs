//! This library provides modular components to build and verify binary Merkle trees
//! with pluggable hash functions.
//!
//! ## Example: Merkle Tree with File Inputs and Proof Verification
//!
//! ```rust
//! use mt_rs::hasher::SHA256Hasher;
//! use mt_rs::merkletree::MerkleTree;
//! use mt_rs::proof::{DefaultProofer, Proofer};
//! use std::fs;
//! use hex::FromHex;
//!
//! let hasher = SHA256Hasher::new();
//!
//! let files = [
//!     fs::read("tests/pics/cubbit.png.enc.0").expect("file 0 not found"),
//!     fs::read("tests/pics/cubbit.png.enc.1").expect("file 1 not found"),
//!     fs::read("tests/pics/cubbit.png.enc.2").expect("file 2 not found"),
//! ];
//!
//! let tree = MerkleTree::new(hasher.clone(), files.clone());
//! let expected_hash: [u8; 32] = [234, 138, 20, 254, 128, 0, 128, 159, 12, 226, 35, 251, 177, 36, 7, 188, 237, 204, 49, 55, 159, 125, 178, 2, 150, 188, 118, 117, 229, 234, 161, 20];
//! let expected_not_valid_hash: [u8; 32] = [234, 0, 20, 254, 128, 0, 128, 159, 12, 226, 35, 251, 177, 36, 7, 188, 237, 204, 49, 55, 159, 125, 178, 2, 150, 188, 118, 117, 229, 234, 161, 20];
//!
//! assert_eq!(tree.height(), 3);
//! assert_eq!(tree.len(), 3);
//! assert_eq!(
//!     *tree.root().hash(),
//!     expected_hash
//! );
//!
//! let proofer = DefaultProofer::new(hasher, tree.leaves().clone());
//!
//! let proof = proofer.generate(0).expect("proof generation failed");
//!
//! assert!(proofer.verify(
//!     &proof,
//!     &files[0],
//!     &expected_hash
//! ));
//!
//! assert!(!proofer.verify(
//!     &proof,
//!     &files[0],
//!     &expected_not_valid_hash
//! ));
//!
//! let proof = proofer.generate(1).expect("proof generation failed");
//!
//! assert!(proofer.verify(
//!     &proof,
//!     &files[1],
//!     &expected_hash
//! ));
//!
//! ```
pub mod fs;
pub mod hasher;
pub mod merkletree;
pub mod node;
pub mod proof;
