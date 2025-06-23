use mt_rs::{hasher::Blake3Hasher, merkletree::MerkleTree};

fn main() {
    // Collect filenames from command line arguments
    let filenames: Vec<String> = std::env::args().skip(1).collect();

    if filenames.is_empty() {
        eprintln!("Usage: cargo run --exmaple merkletree_blake3 -- <file1> <file2> ...");
        std::process::exit(1);
    }

    // Read file contents into a vector of bytes
    let mut file_contents = Vec::new();
    for filename in &filenames {
        match std::fs::read(filename) {
            Ok(contents) => file_contents.push(contents),
            Err(e) => {
                eprintln!("Failed to read file '{}': {}", filename, e);
                std::process::exit(1);
            }
        }
    }

    let hasher = Blake3Hasher::new();
    let tree = MerkleTree::new(hasher.clone(), file_contents.clone());

    println!("{}", tree.root().hash());
}
