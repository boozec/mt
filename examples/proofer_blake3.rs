use mt_rs::{
    fs,
    hasher::Blake3Hasher,
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

    let hasher = Blake3Hasher::new();

    let nodes: Vec<Node> = fs::hash_dir(hasher.clone(), filenames.clone());
    let first_node = nodes[0].clone();

    let proofer = DefaultProofer::new(hasher, nodes);
    let proof = proofer.generate(0).expect("Couldn't generate proof");

    println!(
        "{}",
        proofer.verify_hash(&proof, first_node.hash().to_string(), &root_hash[..])
    );
}
