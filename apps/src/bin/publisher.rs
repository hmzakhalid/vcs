use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{address, Address, Bytes, B256},
    providers::fillers::{
        ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
    },
    providers::{Identity, Provider, ProviderBuilder, RootProvider},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
    transports::BoxTransport,
};
use alloy_primitives::U256;
use eyre::Result;
use num_bigint::BigUint;
use num_traits::ToBytes;
use sha3::{Digest, Keccak256};
use std::env;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Import zk-proof related items
use methods::IS_EVEN_ELF;
use risc0_ethereum_contracts::groth16;
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, VerifierContext};

// Import FHE related
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use rand::thread_rng;
use sha2::Sha256;
use vcs_core::{CiphertextInputs, ComputationInput, ComputationResult};

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract CRISPVoting {
        function verify(bytes32 journalHash, bytes calldata seal) public view;
        function insertLeaf(uint64 id, bytes memory input) public returns (uint256, uint256, uint256);
        function getRoot(uint64 id) public view returns (uint256);
        function displayTree(uint64 id) public view returns (uint256, uint256, uint256);
        function getHash(bytes memory input) public pure returns (bytes32, uint256);
    }
}

type CRISPProvider = FillProvider<
    JoinFill<
        JoinFill<JoinFill<JoinFill<Identity, GasFiller>, NonceFiller>, ChainIdFiller>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<BoxTransport>,
    BoxTransport,
    Ethereum,
>;

pub struct CRISPVotingContract {
    provider: Arc<CRISPProvider>,
    contract_address: Address,
}

impl CRISPVotingContract {
    pub async fn new(rpc_url: &str, private_key: &str, contract_address: &str) -> Result<Self> {
        let signer: PrivateKeySigner = private_key.parse()?;
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_builtin(rpc_url)
            .await?;

        Ok(Self {
            provider: Arc::new(provider),
            contract_address: contract_address.parse()?,
        })
    }

    pub async fn verify(&self, journal_hash: B256, seal: Bytes) -> Result<TransactionReceipt> {
        let contract = CRISPVoting::new(self.contract_address, &self.provider);
        let builder = contract.verify(journal_hash, seal);
        let receipt = builder.send().await?.get_receipt().await?;
        Ok(receipt)
    }

    pub async fn insert_leaf(&self, id: u64, input: Bytes) -> Result<TransactionReceipt> {
        let contract = CRISPVoting::new(self.contract_address, &self.provider);
        let builder = contract.insertLeaf(id, input);
        let result = builder.send().await?.get_receipt().await?;
        Ok(result)
    }

    pub async fn get_root(&self, id: u64) -> Result<String> {
        let contract = CRISPVoting::new(self.contract_address, &self.provider);
        let builder = contract.getRoot(id).call().await?;
        Ok(hex::encode(builder._0.to_be_bytes_vec()))
    }

    pub async fn display_tree(&self, id: u64) -> Result<(U256, U256, U256)> {
        let contract = CRISPVoting::new(self.contract_address, &self.provider);
        let builder = contract.displayTree(id).call().await?;
        Ok((builder._0, builder._1, builder._2))
    }

    pub async fn get_hash(&self, input: Bytes) -> Result<(B256, U256)> {
        let contract = CRISPVoting::new(self.contract_address, &self.provider);
        let builder = contract.getHash(input).call().await?;
        Ok((builder._0, builder._1))
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    // compute_provider();

    let (b32, seal) = tokio::task::spawn_blocking(|| {
        let ct: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let params = create_params();

        let ciphertexts = CiphertextInputs {
            ciphertexts: ct,
            params: params.to_bytes(),
        };

        let compute_input = ComputationInput {
            ciphertexts,
            leaf_hashes: Vec::new(),
            tree_depth: 10,
            zero_node: String::from("0"),
            arity: 2,
        };

        let env = ExecutorEnv::builder()
            .write(&compute_input)
            .unwrap()
            .build()
            .unwrap();

        let receipt = default_prover()
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                IS_EVEN_ELF,
                &ProverOpts::groth16(),
            )
            .unwrap()
            .receipt;

        // Encode the seal with the selector
        let seal = Bytes::from(groth16::encode(receipt.inner.groth16().unwrap().seal.clone()).unwrap());
        let journal = receipt.journal.bytes.clone();
        let journal_hash = Sha256::new().chain_update(&journal).finalize();
        let b32 = B256::from_slice(&journal_hash);

        (b32, seal)
    })
    .await
    .unwrap();

    println!("B32: {:?}", b32);
    println!("Seal: {:?}", seal);

    // // Use async for the rest of the code
    // let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set in the environment");
    // let rpc_url = "http://0.0.0.0:8545";
    // let contract = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
    // let contract_caller = CRISPVotingContract::new(&rpc_url, &private_key, &contract).await?;
    // let id = 9u64;
    // let data: Vec<Bytes> = (1..=6 as u64)
    //     .map(|i| Bytes::from(i.to_be_bytes()))
    //     .collect();
    // for i in 0..data.len() {
    //     contract_caller.insert_leaf(id, data[i].clone()).await?;
    // }
    // let tx = contract_caller.get_root(id).await?;
    // println!("Response: {:?}", tx);
    // let dets = contract_caller.display_tree(id).await?;
    // println!("Response: {:?}", dets);

    Ok(())
}

// Example functions used within the zk-proof process
fn compute_provider() -> Vec<Vec<u8>> {
    let params = create_params();
    let (sk, pk) = generate_keys(&params);
    let inputs = vec![1, 1, 0];
    let incs: Vec<Vec<u8>> = encrypt_inputs(&inputs, &pk, &params)
        .iter()
        .map(|c| c.to_bytes())
        .collect();
    let params_2 = create_params_2();
    let ct1_correct = Ciphertext::from_bytes(&incs[0], &params).unwrap();
    let ct1 = Ciphertext::from_bytes(&incs[0], &params_2).unwrap();
    println!("CT1: {:?}", ct1_correct);
    println!("CT1: {:?}", ct1);
    println!("CT1 == CT1: {:?}", ct1 == ct1_correct);

    incs
}

fn create_params() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(1024)
        .set_plaintext_modulus(65537)
        .set_moduli(&[1152921504606584833])
        .build_arc()
        .expect("Failed to build parameters")
}
fn create_params_2() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(1024)
        .set_plaintext_modulus(32768)
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
