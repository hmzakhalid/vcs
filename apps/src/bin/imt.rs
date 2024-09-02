use alloy_primitives::Keccak256;
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger};
use hex;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;
use std::thread;
use zk_kit_imt::imt::{IMTNode, IMT};

pub fn posidon_hash_function(nodes: Vec<IMTNode>) -> IMTNode {
    println!("Nodes: {:?}", nodes);
    let mut pos = Poseidon::<Fr>::new_circom(2).unwrap();
    let mut fr_elements = Vec::new();
    for node in nodes {
        let clean_node = node.trim_start_matches("0x");
        let node_str = BigUint::from_str_radix(clean_node, 16).unwrap().to_string();
        let fr = Fr::from_str(&node_str).unwrap();
        fr_elements.push(fr);
    }

    let hash: BigInt<4> = pos.hash(&fr_elements).unwrap().into();
    let bytes = hash.to_bytes_be();
    hex::encode(bytes)
}

fn print_imt_nodes(tree: &IMT) {
    println!("IMT Nodes:");
    for (level, nodes) in tree.nodes.iter().enumerate() {
        println!("Level {}:", level);
        for chunk in nodes.chunks(2) {
            match chunk.len() {
                2 => println!("  {:?}, {:?}", chunk[0], chunk[1]),
                1 => println!("  {:?}", chunk[0]),
                _ => (),
            }
        }
    }
}

fn build_merkle_leaf(data: usize) -> String {
    let mut kek = Keccak256::new();
    kek.update(&[data as u8]);
    let hex_data = hex::encode(kek.finalize());
    let clean_data = hex_data.trim_start_matches("0x");
    let val = BigUint::from_str_radix(clean_data, 16).unwrap().to_string();
    let data_field = Fr::from_str(&val).unwrap();
    let pad = Fr::from_str("0").unwrap();
    let mut pos = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash: BigInt<4> = pos.hash(&[data_field, pad]).unwrap().into();
    hex::encode(hash.to_bytes_be())
}

fn build_merkle_tree(data: Vec<IMTNode>, depth: usize, zero: String) -> IMT {
    const ARITY: usize = 2;

    let tree = IMT::new(posidon_hash_function, depth, zero, ARITY, data).unwrap();
    print_imt_nodes(&tree);
    tree
}

fn build_merkle_tree_parallel(data: Vec<IMTNode>, batch_size: usize, full_depth: usize) -> IMTNode {
    let chunks: Vec<Vec<IMTNode>> = data
        .chunks(batch_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    let parallel_tree_depth = (batch_size as f64).log2().ceil() as usize;
    let mut handles = vec![];

    for chunk in chunks {
        let handle = thread::spawn(move || {
            let mut tree = build_merkle_tree(chunk, parallel_tree_depth, "0".to_string());
            tree.root().unwrap()
        });
        handles.push(handle);
    }

    let mut roots = vec![];

    for handle in handles {
        let root = handle.join().unwrap();
        println!("Batch Root: {}", root);
        roots.push(root);
    }

    // Calculate the final tree depth depending on the number elements in the batch: full_depth - log2(batch_size)
    let final_depth = full_depth - (batch_size as f64).log2().ceil() as usize;

    // Get the correct zero node from the IMT tree's zeroes
    // The zero node at the parallel_tree_depth is the one we want because we have already built the tree up to that depth
    let temp_tree = build_merkle_tree(vec![], full_depth, "0".to_string());
    let zero_node = temp_tree.zeroes[parallel_tree_depth].clone();

    let mut final_tree = build_merkle_tree(roots, final_depth, zero_node);
    final_tree.root().unwrap()
}

fn main() {
    let data: Vec<String> = (1..=16).map(|i| build_merkle_leaf(i)).collect();
    let full_depth = 4;

    println!("Building Sequential Merkle Tree...");
    let mut seq_tree = build_merkle_tree(data.clone(), full_depth, "0".to_string());
    let sequential_root = seq_tree.root().unwrap();
    println!("Sequential Root: {}", sequential_root);

    println!("Building Parallel Merkle Tree...");
    // Note: The batch size must be a power of 2
    let parallel_root = build_merkle_tree_parallel(data, 4, full_depth);
    println!("Parallel Root: {}", parallel_root);

    if sequential_root == parallel_root {
        println!("The roots match!");
    } else {
        println!("The roots do not match.");
    }
}
