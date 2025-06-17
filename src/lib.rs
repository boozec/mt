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
//!
//! assert_eq!(tree.height(), 3);
//! assert_eq!(tree.len(), 4);
//! assert_eq!(
//!     tree.root().hash(),
//!     "a08c44656fb3f561619b8747a0d1dabe97126d9ed6e0cafbd7ce08ebe12d55ca"
//! );
//!
//! let proofer = DefaultProofer::new(&hasher, tree.leaves().clone());
//!
//! let proof = proofer.generate(0).expect("proof generation failed");
//!
//! assert!(proofer.verify(
//!     &proof,
//!     &files[0],
//!     "a08c44656fb3f561619b8747a0d1dabe97126d9ed6e0cafbd7ce08ebe12d55ca",
//!     &hasher
//! ));
//!
//! assert!(!proofer.verify(
//!     &proof,
//!     &files[0],
//!     "a08c44656fb3f561619b87_NOT_VALID_HASH_9ed6e0cafbd7ce08ebe12d55ca",
//!     &hasher
//! ));
//!
//! let proof = proofer.generate(1).expect("proof generation failed");
//!
//! assert!(proofer.verify(
//!     &proof,
//!     &files[1],
//!     "a08c44656fb3f561619b8747a0d1dabe97126d9ed6e0cafbd7ce08ebe12d55ca",
//!     &hasher
//! ));
//!
//! ```
pub mod hasher;
pub mod merkletree;
pub mod node;
pub mod proof;
