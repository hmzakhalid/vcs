pub mod merkle_tree;
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_traits::{Deserialize, DeserializeParametrized, Serialize};
use std::sync::Arc;
use merkle_tree::MerkleTree;
use sha3::{Digest, Keccak256};


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ComputeResult {
    pub ciphertext_hash: Vec<u8>,
    pub params_hash: Vec<u8>,
    pub merkle_root: Vec<u8>,
}

pub type FHEProcessor = fn(&FHEInputs) -> Vec<u8>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FHEInputs {
    pub ciphertexts: Vec<(Vec<u8>, u64)>,
    pub params: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ComputeInput {
    pub fhe_inputs: FHEInputs,
    pub leaf_hashes: Vec<String>,
}

impl ComputeInput {
    pub fn process(&self, fhe_processor: FHEProcessor) -> ComputeResult {
        let processed_ciphertext = (fhe_processor)(&self.fhe_inputs);
        let processed_hash = Keccak256::digest(&processed_ciphertext).to_vec();
        let params_hash = Keccak256::digest(&self.fhe_inputs.params).to_vec();

        let merkle_root = MerkleTree {
            leaf_hashes: self.leaf_hashes.clone(),
        }
        .build_tree()
        .root()
        .unwrap();

        ComputeResult {
            ciphertext_hash: processed_hash,
            params_hash,
            merkle_root: hex::decode(merkle_root).unwrap(),
        }
    }
}


pub fn fhe_processor(fhe_inputs: &FHEInputs) -> Vec<u8> {
    let params = Arc::new(BfvParameters::try_deserialize(&fhe_inputs.params).unwrap());

    let mut sum = Ciphertext::zero(&params);
    for ciphertext_bytes in &fhe_inputs.ciphertexts {
        let ciphertext = Ciphertext::from_bytes(&ciphertext_bytes.0, &params).unwrap();
        sum += &ciphertext;
    }

    sum.to_bytes()
}