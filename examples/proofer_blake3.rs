use mt_rs::{
    hasher::{Blake3Hasher, Hasher},
    node::Node,
    proof::{DefaultProofer, Proofer},
};

fn main() {
    let root_hash = match std::env::args().nth(1) {
        Some(hash) => hash,
        None => {
            eprintln!(
                "Usage: cargo run --example proofer_blake3 -- <root_hash> <file1> <file2> ..."
            );
            std::process::exit(1);
        }
    };

    let filenames: Vec<String> = std::env::args().skip(2).collect();
    if filenames.is_empty() {
        eprintln!("Usage: cargo run --example proofer_blake3 -- <root_hash> <file1> <file2> ...");
        std::process::exit(1);
    }

    let mut nodes: Vec<Node> = Vec::new();
    for filename in &filenames {
        match std::fs::read(filename) {
            Ok(contents) => {
                let hash = Blake3Hasher::new().hash(&contents);
                nodes.push(Node::new_leaf(&contents, hash));
            }
            Err(e) => {
                eprintln!("Failed to read file '{}': {}", filename, e);
                std::process::exit(1);
            }
        }
    }

    let first_node = nodes[0].clone();
    let hasher = Blake3Hasher::new();
    let proofer = DefaultProofer::new(&hasher, nodes);
    let proof = proofer.generate(0).expect("Couldn't generate proof");

    println!(
        "{}",
        proofer.verify(&proof, first_node.data(), &root_hash[..], &hasher)
    );
}
