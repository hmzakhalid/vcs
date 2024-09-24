use alloy::sol_types::SolValue;
use alloy_sol_types::{sol, SolInterface};
use anyhow::Result;
use ethers::prelude::*;
use methods::IS_EVEN_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::{env, sync::Arc};
use vcs_core::{merkle_tree::MerkleTree, ComputeInput, ComputeResult, FHEInputs};

// `IEvenNumber` interface automatically generated via the alloy `sol!` macro.
sol! {
    interface IEvenNumber {
        event Verified(bytes journal);
        function set(uint256 x, bytes calldata seal);
        function verify(bytes memory journal, bytes calldata seal);
        function verifyFields(bytes32 ctHash, bytes32 paramHash, bytes32 rootHash, bytes calldata seal);
    }
}

/// Wrapper of a `SignerMiddleware` client to send transactions to the given
/// contract's `Address`.
pub struct TxSender {
    chain_id: u64,
    client: SignerMiddleware<Provider<Http>, Wallet<k256::ecdsa::SigningKey>>,
    contract: Address,
}

impl TxSender {
    /// Creates a new `TxSender`.
    pub fn new() -> Result<Self> {
        let private_key =
            env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set in the environment");
        let rpc_url = "http://0.0.0.0:8545";
        let contract_address = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9";
        let chain_id = 31337;
        println!("Private Key: {:?}", private_key);
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet: LocalWallet = private_key.parse::<LocalWallet>()?.with_chain_id(chain_id);
        let client = SignerMiddleware::new(provider.clone(), wallet.clone());
        let contract = contract_address.parse::<Address>()?;

        Ok(TxSender {
            chain_id,
            client,
            contract,
        })
    }

    /// Send a transaction with the given calldata.
    pub async fn send(&self, calldata: Vec<u8>) -> Result<Option<TransactionReceipt>> {
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .to(self.contract)
            .from(self.client.address())
            .data(calldata);

        log::info!("Transaction request: {:?}", &tx);

        let tx = self.client.send_transaction(tx, None).await?.await?;

        log::info!("Transaction receipt: {:?}", &tx);

        Ok(tx)
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Create a new transaction sender using the parsed arguments.
    let tx_sender = TxSender::new()?;
    // let (journal, journal_bytes, seal) = tokio::task::spawn_blocking(|| {
    //     let (ct, params) = compute_provider();

    //     let fhe_inputs = FHEInputs {
    //         ciphertexts: ct,
    //         params,
    //     };

    //     let mut compute_input = ComputeInput {
    //         fhe_inputs: fhe_inputs.clone(),
    //         leaf_hashes: Vec::new(),
    //     };

    //     let mut tree_handler = MerkleTree::new();
    //     tree_handler.compute_leaf_hashes(&fhe_inputs.ciphertexts);
    //     compute_input.leaf_hashes = tree_handler.leaf_hashes.clone();

    //     let env = ExecutorEnv::builder()
    //         .write(&compute_input)
    //         .unwrap()
    //         .build()
    //         .unwrap();

    //     let receipt = default_prover()
    //         .prove_with_ctx(
    //             env,
    //             &VerifierContext::default(),
    //             IS_EVEN_ELF,
    //             &ProverOpts::groth16(),
    //         )
    //         .unwrap()
    //         .receipt;

    //     // Encode the seal with the selector.
    //     let seal = groth16::encode(receipt.inner.groth16().unwrap().seal.clone()).unwrap();
    //     // Extract the journal from the receipt.
    //     let journal: ComputeResult = receipt.journal.decode().unwrap();

    //     let journal_bytes = receipt.journal.bytes.clone();
    //     (journal, journal_bytes, seal)
    // })
    // .await
    // .unwrap();
    let journal = ComputeResult {
        ciphertext_hash: vec![
            146, 147, 8, 47, 14, 198, 46, 13, 4, 241, 161, 127, 25, 244, 85, 168, 161, 110, 153,
            178, 63, 100, 150, 100, 76, 143, 11, 154, 185, 169, 252, 194,
        ],
        params_hash: vec![
            59, 114, 156, 230, 114, 3, 182, 0, 79, 254, 253, 77, 175, 74, 253, 109, 35, 127, 182,
            49, 97, 191, 108, 68, 98, 49, 20, 206, 71, 45, 4, 27,
        ],
        merkle_root: vec![
            7, 251, 148, 83, 209, 88, 155, 64, 97, 152, 166, 77, 167, 12, 201, 84, 133, 32, 212,
            148, 156, 211, 100, 19, 159, 143, 157, 138, 7, 129, 146, 180,
        ],
    };

    let journal_bytes = vec![
        32, 0, 0, 0, 146, 0, 0, 0, 147, 0, 0, 0, 8, 0, 0, 0, 47, 0, 0, 0, 14, 0, 0, 0, 198, 0, 0,
        0, 46, 0, 0, 0, 13, 0, 0, 0, 4, 0, 0, 0, 241, 0, 0, 0, 161, 0, 0, 0, 127, 0, 0, 0, 25, 0,
        0, 0, 244, 0, 0, 0, 85, 0, 0, 0, 168, 0, 0, 0, 161, 0, 0, 0, 110, 0, 0, 0, 153, 0, 0, 0,
        178, 0, 0, 0, 63, 0, 0, 0, 100, 0, 0, 0, 150, 0, 0, 0, 100, 0, 0, 0, 76, 0, 0, 0, 143, 0,
        0, 0, 11, 0, 0, 0, 154, 0, 0, 0, 185, 0, 0, 0, 169, 0, 0, 0, 252, 0, 0, 0, 194, 0, 0, 0,
        32, 0, 0, 0, 59, 0, 0, 0, 114, 0, 0, 0, 156, 0, 0, 0, 230, 0, 0, 0, 114, 0, 0, 0, 3, 0, 0,
        0, 182, 0, 0, 0, 0, 0, 0, 0, 79, 0, 0, 0, 254, 0, 0, 0, 253, 0, 0, 0, 77, 0, 0, 0, 175, 0,
        0, 0, 74, 0, 0, 0, 253, 0, 0, 0, 109, 0, 0, 0, 35, 0, 0, 0, 127, 0, 0, 0, 182, 0, 0, 0, 49,
        0, 0, 0, 97, 0, 0, 0, 191, 0, 0, 0, 108, 0, 0, 0, 68, 0, 0, 0, 98, 0, 0, 0, 49, 0, 0, 0,
        20, 0, 0, 0, 206, 0, 0, 0, 71, 0, 0, 0, 45, 0, 0, 0, 4, 0, 0, 0, 27, 0, 0, 0, 32, 0, 0, 0,
        7, 0, 0, 0, 251, 0, 0, 0, 148, 0, 0, 0, 83, 0, 0, 0, 209, 0, 0, 0, 88, 0, 0, 0, 155, 0, 0,
        0, 64, 0, 0, 0, 97, 0, 0, 0, 152, 0, 0, 0, 166, 0, 0, 0, 77, 0, 0, 0, 167, 0, 0, 0, 12, 0,
        0, 0, 201, 0, 0, 0, 84, 0, 0, 0, 133, 0, 0, 0, 32, 0, 0, 0, 212, 0, 0, 0, 148, 0, 0, 0,
        156, 0, 0, 0, 211, 0, 0, 0, 100, 0, 0, 0, 19, 0, 0, 0, 159, 0, 0, 0, 143, 0, 0, 0, 157, 0,
        0, 0, 138, 0, 0, 0, 7, 0, 0, 0, 129, 0, 0, 0, 146, 0, 0, 0, 180, 0, 0, 0,
    ];

    let seal = vec![
        49, 15, 229, 152, 3, 26, 216, 30, 130, 50, 179, 110, 194, 244, 224, 55, 74, 179, 204, 135,
        168, 105, 102, 98, 226, 236, 12, 115, 12, 81, 249, 179, 48, 89, 94, 140, 25, 216, 209, 132,
        113, 116, 64, 30, 52, 54, 133, 98, 44, 83, 63, 111, 9, 77, 142, 34, 169, 181, 158, 159, 18,
        5, 89, 99, 239, 28, 24, 134, 15, 169, 63, 29, 202, 25, 173, 81, 204, 97, 92, 47, 251, 148,
        247, 140, 68, 231, 60, 247, 8, 186, 155, 246, 33, 87, 8, 252, 170, 88, 157, 38, 24, 74,
        239, 55, 71, 235, 129, 23, 9, 175, 99, 223, 132, 61, 213, 61, 46, 184, 253, 30, 137, 219,
        60, 82, 176, 59, 166, 113, 202, 97, 167, 169, 15, 191, 209, 236, 155, 59, 216, 100, 239,
        201, 117, 176, 41, 13, 166, 146, 21, 105, 189, 184, 176, 61, 88, 161, 202, 98, 33, 164,
        216, 105, 154, 82, 39, 14, 110, 229, 157, 182, 183, 253, 10, 190, 253, 86, 1, 253, 67, 106,
        103, 114, 81, 229, 243, 162, 148, 34, 85, 17, 198, 244, 87, 70, 162, 200, 15, 48, 191, 68,
        42, 38, 165, 109, 123, 157, 110, 147, 191, 25, 89, 232, 225, 233, 110, 106, 160, 109, 147,
        212, 172, 92, 249, 133, 144, 75, 35, 246, 29, 225, 46, 110, 186, 34, 118, 196, 217, 203,
        180, 235, 20, 226, 192, 180, 253, 91, 30, 149, 139, 236, 66, 237, 175, 56, 64, 167, 104,
        215, 74, 168,
    ];

    println!("Journal: {:?}", journal);
    println!("Journal Bytes: {:?}", journal_bytes);
    println!("Seal: {:?}", seal);

    fn vector_to_bytes32(vector: &Vec<u8>) -> [u8; 32] {
        let mut array = [0u8; 32];
        array.copy_from_slice(&vector[0..32]);
        array
    }

    // Assuming you have the following vectors from your journal:
    let ct_hash = vector_to_bytes32(&journal.ciphertext_hash);
    let param_hash = vector_to_bytes32(&journal.params_hash);
    let root_hash = vector_to_bytes32(&journal.merkle_root);

    let calldata = IEvenNumber::IEvenNumberCalls::verifyFields(IEvenNumber::verifyFieldsCall {
        ctHash: ct_hash.into(),
        paramHash: param_hash.into(),
        rootHash: root_hash.into(),
        seal: seal.into(),
    })
    .abi_encode();

    // Send transaction: Finally, the TxSender component sends the transaction to the Ethereum blockchain,
    match tx_sender.send(calldata).await {
        Ok(Some(receipt)) => {
            println!("Transaction receipt: {:?}", receipt.transaction_hash);
            // Step 1: Check if there's return data in the receipt
            if let logs = receipt.logs {
                if let Some(return_data) = logs.get(0) {
                    // Step 2: Decode the return data (journal) from the transaction
                    let return_bytes = return_data.data.0.clone();

                    // Step 3: Decode the returned `journal` bytes using Alloy
                    // Alloy's `AbiDecode` trait allows decoding ABI encoded return values
                    // Assuming journal is `bytes`, we just retrieve the raw bytes
                    let decoded_journal: Vec<u8> =
                        Vec::<u8>::abi_decode(&return_bytes, true).unwrap();

                    println!("Returned journal: {:?}", decoded_journal);
                }
            }
        }
        Ok(None) => {
            println!("Transaction failed");
        }
        Err(e) => {
            println!("Transaction error: {:?}", e);
        }
    }

    Ok(())
}

// Example functions used within the zk-proof process
fn compute_provider() -> (Vec<(Vec<u8>, u64)>, Vec<u8>) {
    let params = create_params();
    let (_sk, pk) = generate_keys(&params);
    let inputs = vec![1, 1, 0];
    let incs: Vec<(Vec<u8>, u64)> = encrypt_inputs(&inputs, &pk, &params)
        .iter()
        .map(|c| (c.to_bytes(), 1))
        .collect();

    (incs, params.to_bytes())
}

fn create_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(1024)
        .set_plaintext_modulus(65537)
        .set_moduli(&[1152921504606584833])
        .build_arc()
        .expect("Failed to build parameters")
}

fn generate_keys(params: &Arc<BfvParameters>) -> (SecretKey, PublicKey) {
    let mut rng = thread_rng();
    let sk = SecretKey::random(params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    (sk, pk)
}

fn encrypt_inputs(inputs: &[u64], pk: &PublicKey, params: &Arc<BfvParameters>) -> Vec<Ciphertext> {
    let mut rng = thread_rng();
    inputs
        .iter()
        .map(|&input| {
            let pt = Plaintext::try_encode(&[input], Encoding::poly(), params)
                .expect("Failed to encode plaintext");
            pk.try_encrypt(&pt, &mut rng).expect("Failed to encrypt")
        })
        .collect()
}
