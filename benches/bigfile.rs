use criterion::{Criterion, criterion_group, criterion_main};
use mt_rs::{
    hasher::{Blake3Hasher, Hasher, Keccak256Hasher, SHA256Hasher},
    merkletree::MerkleTree,
    proof::{DefaultProofer, Proofer},
};
use rand::{RngCore, rngs::OsRng};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

// Create files `filenames` with random data with a size of `size` MB.
fn setup_files(filenames: &Vec<String>, size: usize) -> std::io::Result<Vec<Vec<u8>>> {
    for filename in filenames.iter() {
        if !Path::new(filename).exists() {
            let file = File::create(filename)?;
            let mut writer = BufWriter::new(file);

            let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer

            // 1 MB * size = total bytes
            for _ in 0..size {
                // Fill buffer with random bytes
                OsRng.fill_bytes(&mut buffer);
                writer.write_all(&buffer)?;
            }

            writer.flush()?;
        }
    }

    let files: Vec<Vec<u8>> = filenames
        .iter()
        .map(|filename| fs::read(filename).expect("file not found"))
        .collect();

    Ok(files)
}

fn cleanup_files(filenames: &Vec<String>) -> std::io::Result<()> {
    for filename in filenames.iter() {
        if Path::new(filename).exists() {
            fs::remove_file(filename)?;
        }
    }
    Ok(())
}

fn test_merkle_tree<H: Hasher + Clone + 'static>(hasher: H, files: &Vec<Vec<u8>>) {
    let tree = MerkleTree::new(hasher.clone(), files);
    let proofer = DefaultProofer::new(hasher, tree.leaves().clone());
    let root = tree.root();
    let root_hash = root.hash();

    for i in 0..files.len() {
        let proof = proofer.generate(i).expect("proof generation failed");
        assert!(proofer.verify(&proof, &files[i], root_hash));
    }
}

/// Example of a MarkleTree with 10 nodes which use SHA256 algorithm to make hashes.
/// Each node has a size of 5, 10 or 15 MB.
/// Also, it verifies each node path with a proofer O(n).
fn bench_large_merkle_tree_sha256(c: &mut Criterion) {
    let filenames: Vec<String> = (1..=10).map(|i| format!("file-{i}.dat")).collect();

    let mut group = c.benchmark_group("MerkleTree");
    group.sample_size(10);
    for size in [5, 10, 15] {
        group.bench_function(
            format!("MerkleTree creation and validation with 10 nodes and SHA256 algorithm. {size} MB per each file."),
            |b| {
                let files = setup_files(&filenames, size).expect("failed to allocate new files");

                b.iter(|| {
                    let hasher = SHA256Hasher::new();
                    test_merkle_tree(hasher, &files);
                });
                cleanup_files(&filenames).expect("failed to deallocate data");
            },
        );
    }
    group.finish();
}

/// Example of a MarkleTree with 10 nodes which use Keccak256 algorithm to make hashes.
/// Each node has a size of 5, 10 or 15 MB.
/// Also, it verifies each node path with a proofer O(n).
fn bench_large_merkle_tree_keccak256(c: &mut Criterion) {
    let filenames: Vec<String> = (1..=10).map(|i| format!("file-{i}.dat")).collect();

    let mut group = c.benchmark_group("MerkleTree");
    group.sample_size(10);
    for size in [5, 10, 15] {
        group.bench_function(
            format!("MerkleTree creation and validation with 10 nodes and Keccak256 algorithm. {size} MB per each file."),
            |b| {
                let files = setup_files(&filenames, size).expect("failed to allocate new files");

                b.iter(|| {
                    let hasher = Keccak256Hasher::new();
                    test_merkle_tree(hasher, &files);
                });
                cleanup_files(&filenames).expect("failed to deallocate data");
            },
        );
    }
    group.finish();
}

/// Example of a MarkleTree with 10 nodes which use Blake3 algorithm to make hashes.
/// Each node has a size of 5, 10 or 15 MB.
/// Also, it verifies each node path with a proofer O(n).
fn bench_large_merkle_tree_blake3(c: &mut Criterion) {
    let filenames: Vec<String> = (1..=10).map(|i| format!("file-{i}.dat")).collect();

    let mut group = c.benchmark_group("MerkleTree");
    group.sample_size(10);
    for size in [5, 10, 15] {
        group.bench_function(
            format!("MerkleTree creation and validation with 10 nodes and Keccak256 algorithm. {size} MB per each file."),
            |b| {
                let files = setup_files(&filenames, size).expect("failed to allocate new files");

                b.iter(|| {
                    let hasher = Blake3Hasher::new();
                    test_merkle_tree(hasher, &files);
                });
                cleanup_files(&filenames).expect("failed to deallocate data");
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_large_merkle_tree_sha256,
    bench_large_merkle_tree_keccak256,
    bench_large_merkle_tree_blake3
);
criterion_main!(benches);
