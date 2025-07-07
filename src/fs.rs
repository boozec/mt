//! Provides the module used for filesystem operations made by this library.

use std::path::Path;

use crate::{hasher::Hasher, node::Node};

/// Reads the entire content of a file into a `Vec<u8>`.
///
/// If the file cannot be read, an error message is printed to stderr, and the program exits.
///
/// `path` is a reference to a `String` representing the path to the file.
fn read_file_content(path: &String) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(contents) => contents,
        Err(e) => {
            eprintln!("Failed to read file '{}': {}", path, e);
            std::process::exit(1);
        }
    }
}

/// Recursively hashes the contents of files and directories.
///
/// This function iterates through a list of filenames. For each file, it reads its content,
/// hashes it using the provided `Hasher`, and creates a leaf `Node`. If an entry is a directory,
/// it recursively calls itself to hash the directory's contents and extends the current
/// list of nodes with the results.
pub fn hash_dir<H>(hasher: H, filenames: Vec<String>) -> Vec<Node>
where
    H: Hasher + 'static + std::marker::Sync + Clone,
{
    let mut nodes: Vec<Node> = vec![];
    for filename in &filenames {
        let file = Path::new(filename);
        if file.is_file() {
            let hash = hasher.hash(read_file_content(filename).as_slice());

            nodes.push(Node::new_leaf(hash));
        } else if file.is_dir() {
            let mut filenames_in_dir: Vec<String> = file
                .read_dir()
                .unwrap()
                .map(|entry| String::from(entry.unwrap().path().to_str().unwrap()))
                .collect();

            filenames_in_dir.sort();

            nodes.extend(hash_dir(hasher.clone(), filenames_in_dir));
        }
    }

    nodes
}
