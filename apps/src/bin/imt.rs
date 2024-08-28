use alloy_primitives::Keccak256;
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger};
use hex;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::Num;
use std::str::FromStr;
use zk_kit_imt::imt::IMT;

pub fn posidon_hash_function(nodes: Vec<String>) -> String {
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

fn main() {
    const ZERO: &str = "0";
    const DEPTH: usize = 32;
    const ARITY: usize = 2;

    let mut tree = IMT::new(
        posidon_hash_function,
        DEPTH,
        ZERO.to_string(),
        ARITY,
        vec![],
    )
    .unwrap();

    let mut pos = Poseidon::<Fr>::new_circom(2).unwrap();
    let data: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];

    let mut kek = Keccak256::new();
    kek.update(&data);
    let hex_data = hex::encode(kek.finalize());
    let clean_data = hex_data.trim_start_matches("0x");
    let val = BigUint::from_str_radix(clean_data, 16).unwrap().to_string();
    let data_field = Fr::from_str(&val).unwrap();
    let pad = Fr::from_str("0").unwrap();
    let hash: BigInt<4> = pos.hash(&[data_field, pad]).unwrap().into();
    let hash = hex::encode(hash.to_bytes_be());
    tree.insert(hash).unwrap();
    let root = tree.root().unwrap();

    println!("Root: {}", root);
}

// "0x173989c01a55a9290a17b36dad1412a0e03f55cad58de9ab21c44a6fdfeda2e0"
// 19067983348140929614931157778076933155244721475585190732676631703400658318080
