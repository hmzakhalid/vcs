use alloy::primitives::Bytes;
use sha3::{Digest, Keccak256};
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger};
use hex;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;
use std::thread;
use lean_imt::{IMTNode, LeanIMT};

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

// fn print_imt_nodes(tree: &LeanIMT) {
//     println!("IMT Nodes:");
//     for (level, nodes) in tree.nodes.iter().enumerate() {
//         println!("Level {}:", level);
//         for chunk in nodes.chunks(2) {
//             match chunk.len() {
//                 2 => println!("  {:?}, {:?}", chunk[0], chunk[1]),
//                 1 => println!("  {:?}", chunk[0]),
//                 _ => (),
//             }
//         }
//     }
// }

fn build_merkle_leaf_bytes(data: Bytes, count: String) -> String {
    println!("Data: {}", data);
    let hex_data = hex::encode(Keccak256::digest(&data));
    println!("Hex Data: {}", hex_data);
    let clean_data = hex_data.trim_start_matches("0x");
    let val = BigUint::from_str_radix(clean_data, 16).unwrap().to_string();
    let data_field = Fr::from_str(&val).unwrap();
    let pad = Fr::from_str(&count).unwrap();
    let mut pos = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash: BigInt<4> = pos.hash(&[data_field, pad]).unwrap().into();
    hex::encode(hash.to_bytes_be())
}

fn build_merkle_leaf(data: usize) -> String {
    println!("Data: {}", data);
    let hex_data = hex::encode(Keccak256::digest(&[data as u8]));
    println!("Hex Data: {}", hex_data);
    let clean_data = hex_data.trim_start_matches("0x");
    let val = BigUint::from_str_radix(clean_data, 16).unwrap().to_string();
    let data_field = Fr::from_str(&val).unwrap();
    let pad = Fr::from_str(&( data - 1 as usize).to_string()).unwrap();
    let mut pos = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash: BigInt<4> = pos.hash(&[data_field, pad]).unwrap().into();
    hex::encode(hash.to_bytes_be())
}

fn build_merkle_tree(data: Vec<IMTNode>) -> LeanIMT {
    let mut tree = LeanIMT::new(posidon_hash_function);
    tree.insert_many(data).unwrap();
    // print_imt_nodes(&tree);
    tree
}

fn build_merkle_tree_parallel(data: Vec<IMTNode>, batch_size: usize) -> IMTNode {
    let chunks: Vec<Vec<IMTNode>> = data
        .chunks(batch_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    // let parallel_tree_depth = (batch_size as f64).log2().ceil() as usize;
    let mut handles = vec![];

    for chunk in chunks {
        let handle = thread::spawn(move || {
            let tree = build_merkle_tree(chunk);
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
    // let final_depth = full_depth - parallel_tree_depth;

    // Get the correct zero node from the IMT tree's zeroes
    // The zero node at the parallel_tree_depth is the one we want because we have already built the tree up to that depth
    // let temp_tree = build_merkle_tree(vec![], full_depth, "0".to_string());
    // let zero_node = temp_tree.zeroes[parallel_tree_depth].clone();

    let final_tree = build_merkle_tree(roots);
    final_tree.root().unwrap()
}

fn main() {
    let data: Vec<String> = (1..=6 as u64).map(|i| build_merkle_leaf_bytes( Bytes::from(i.to_be_bytes()), (i-1u64).to_string())).collect();
    // println!("Data: {:?}", data);
    println!("Building Sequential Merkle Tree...");
    let seq_tree = build_merkle_tree(data.clone());
    let sequential_root = seq_tree.root().unwrap();
    println!("Sequential Root: {}", sequential_root);

    // println!("Building Parallel Merkle Tree...");
    // // Note: The batch size must be a power of 2
    // let parallel_root = build_merkle_tree_parallel(data, 4);
    // println!("Parallel Root: {}", parallel_root);

    // if sequential_root == parallel_root {
    //     println!("The roots match!");
    // } else {
    //     println!("The roots do not match.");
    // }
}

// 05709d7c34dd59462eef388b170622a527ad94462b1ff757618fdc24a5f8b94e // IMT
// 05709d7c34dd59462eef388b170622a527ad94462b1ff757618fdc24a5f8b94e // Contract