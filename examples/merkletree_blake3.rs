use hex::ToHex;
use mt_rs::{hasher::Blake3Hasher, merkletree::MerkleTree};

fn main() {
    // Collect filenames from command line arguments
    let filenames: Vec<String> = std::env::args().skip(1).collect();

    if filenames.is_empty() {
        eprintln!("Usage: cargo run --example merkletree_blake3 -- <file1> <file2> ...");
        std::process::exit(1);
    }

    // Read file contents into a vector of bytes
    let hasher = Blake3Hasher::new();

    let tree = MerkleTree::from_paths(hasher, filenames);

    println!("{}", tree.root().hash().encode_hex::<String>());
}
