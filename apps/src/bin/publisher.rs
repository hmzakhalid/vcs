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
            218, 235, 206, 94, 243, 239, 26, 230, 170, 112, 57, 97, 13, 35, 122, 75, 62, 209, 19,
            216, 61, 210, 76, 238, 32, 66, 238, 50, 155, 155, 143, 91,
        ],
        params_hash: vec![
            100, 48, 60, 53, 179, 221, 6, 168, 250, 56, 160, 96, 17, 36, 27, 212, 110, 220, 118,
            14, 222, 129, 206, 129, 135, 181, 150, 4, 27, 169, 131, 0,
        ],
        merkle_root: vec![
            45, 105, 101, 77, 208, 216, 239, 14, 8, 47, 7, 56, 49, 152, 164, 210, 47, 35, 17, 126,
            147, 74, 21, 106, 133, 216, 231, 1, 102, 255, 58, 179,
        ],
    };

    let journal_bytes = vec![
        32, 0, 0, 0, 218, 0, 0, 0, 235, 0, 0, 0, 206, 0, 0, 0, 94, 0, 0, 0, 243, 0, 0, 0, 239, 0,
        0, 0, 26, 0, 0, 0, 230, 0, 0, 0, 170, 0, 0, 0, 112, 0, 0, 0, 57, 0, 0, 0, 97, 0, 0, 0, 13,
        0, 0, 0, 35, 0, 0, 0, 122, 0, 0, 0, 75, 0, 0, 0, 62, 0, 0, 0, 209, 0, 0, 0, 19, 0, 0, 0,
        216, 0, 0, 0, 61, 0, 0, 0, 210, 0, 0, 0, 76, 0, 0, 0, 238, 0, 0, 0, 32, 0, 0, 0, 66, 0, 0,
        0, 238, 0, 0, 0, 50, 0, 0, 0, 155, 0, 0, 0, 155, 0, 0, 0, 143, 0, 0, 0, 91, 0, 0, 0, 32, 0,
        0, 0, 100, 0, 0, 0, 48, 0, 0, 0, 60, 0, 0, 0, 53, 0, 0, 0, 179, 0, 0, 0, 221, 0, 0, 0, 6,
        0, 0, 0, 168, 0, 0, 0, 250, 0, 0, 0, 56, 0, 0, 0, 160, 0, 0, 0, 96, 0, 0, 0, 17, 0, 0, 0,
        36, 0, 0, 0, 27, 0, 0, 0, 212, 0, 0, 0, 110, 0, 0, 0, 220, 0, 0, 0, 118, 0, 0, 0, 14, 0, 0,
        0, 222, 0, 0, 0, 129, 0, 0, 0, 206, 0, 0, 0, 129, 0, 0, 0, 135, 0, 0, 0, 181, 0, 0, 0, 150,
        0, 0, 0, 4, 0, 0, 0, 27, 0, 0, 0, 169, 0, 0, 0, 131, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 45,
        0, 0, 0, 105, 0, 0, 0, 101, 0, 0, 0, 77, 0, 0, 0, 208, 0, 0, 0, 216, 0, 0, 0, 239, 0, 0, 0,
        14, 0, 0, 0, 8, 0, 0, 0, 47, 0, 0, 0, 7, 0, 0, 0, 56, 0, 0, 0, 49, 0, 0, 0, 152, 0, 0, 0,
        164, 0, 0, 0, 210, 0, 0, 0, 47, 0, 0, 0, 35, 0, 0, 0, 17, 0, 0, 0, 126, 0, 0, 0, 147, 0, 0,
        0, 74, 0, 0, 0, 21, 0, 0, 0, 106, 0, 0, 0, 133, 0, 0, 0, 216, 0, 0, 0, 231, 0, 0, 0, 1, 0,
        0, 0, 102, 0, 0, 0, 255, 0, 0, 0, 58, 0, 0, 0, 179, 0, 0, 0,
    ];

    let seal = vec![
        49, 15, 229, 152, 28, 129, 212, 223, 48, 107, 136, 253, 184, 123, 209, 107, 206, 238, 220,
        115, 181, 179, 160, 241, 144, 150, 103, 203, 180, 175, 238, 124, 124, 169, 152, 101, 9, 82,
        92, 180, 29, 233, 237, 53, 31, 223, 117, 102, 216, 236, 77, 143, 94, 138, 97, 39, 48, 109,
        181, 62, 17, 182, 172, 225, 8, 142, 91, 86, 25, 222, 228, 21, 239, 195, 80, 53, 200, 82,
        235, 132, 219, 168, 216, 134, 191, 5, 28, 85, 18, 107, 118, 12, 108, 86, 164, 126, 171,
        101, 61, 77, 35, 232, 162, 29, 63, 194, 29, 51, 166, 222, 111, 26, 53, 184, 250, 148, 206,
        211, 222, 75, 28, 95, 31, 164, 31, 191, 56, 173, 186, 78, 8, 14, 18, 224, 130, 100, 10,
        139, 149, 201, 177, 53, 168, 33, 54, 15, 230, 140, 8, 254, 226, 210, 118, 1, 89, 91, 239,
        49, 26, 246, 145, 105, 240, 67, 21, 28, 239, 95, 200, 165, 5, 97, 203, 123, 107, 24, 174,
        141, 0, 129, 11, 237, 40, 107, 81, 186, 59, 12, 118, 75, 242, 161, 46, 244, 73, 25, 16,
        111, 79, 226, 185, 156, 94, 179, 207, 223, 244, 169, 254, 38, 65, 55, 82, 12, 81, 142, 51,
        193, 168, 132, 108, 205, 89, 127, 93, 180, 154, 10, 16, 169, 211, 136, 233, 167, 103, 134,
        69, 50, 68, 195, 121, 103, 112, 43, 240, 127, 51, 57, 57, 129, 192, 178, 193, 143, 64, 151,
        226, 190, 244, 195,
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
