use zk_kit_imt::imt::IMT;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey,
};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
};
use rand::thread_rng;
use std::sync::Arc;

fn compute_provider() -> Vec<Vec<u8>> {
    let params = create_params();
    let (sk, pk) = generate_keys(&params);
    let inputs = vec![1, 1, 0];
    let ciphertexts = encrypt_inputs(&inputs, &pk, &params);
    ciphertexts.iter().map(|c| c.to_bytes()).collect()
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

fn encrypt_inputs(
    inputs: &[u64],
    pk: &PublicKey,
    params: &Arc<BfvParameters>,
) -> Vec<Ciphertext> {
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


fn hash_function(nodes: Vec<String>) -> String {
    nodes.join("-")
}

fn main() {
    const ZERO: &str = "zero";
    const DEPTH: usize = 3;
    const ARITY: usize = 2;

    /*
     *  To create an instance of an IMT, you need to provide a hash function,
     *  the depth of the tree, the zero value, the arity of the tree and an initial list of leaves.
     */
    let mut tree = IMT::new(hash_function, DEPTH, ZERO.to_string(), ARITY, vec![]).unwrap();

    // Insert (incrementally) a leaf with value "some-leaf"
    tree.insert("some-leaf".to_string()).unwrap();
    // Insert (incrementally) a leaf with value "another_leaf"
    tree.insert("another_leaf".to_string()).unwrap();

    let root = tree.root().unwrap();
    println!("imt tree root: {root}");
    assert!(root == "some-leaf-another_leaf-zero-zero-zero-zero-zero-zero");

    let depth = tree.depth();
    println!("imt tree depth: {depth}");
    assert!(depth == 3);

    let arity = tree.arity();
    println!("imt tree arity: {arity}");
    assert!(arity == 2);

    let leaves = tree.leaves();
    println!("imt tree leaves: {:?}", leaves);
    assert!(leaves == vec!["some-leaf", "another_leaf"]);

    // Delete the leaf at index 0
    assert!(tree.delete(0).is_ok());
    let root = tree.root().unwrap();
    println!("imt tree root: {root}");
    assert!(root == "zero-another_leaf-zero-zero-zero-zero-zero-zero");

    // Create a proof for the leaf at index 1
    let proof = tree.create_proof(1);
    assert!(proof.is_ok());
    let proof = proof.unwrap();
    assert!(tree.verify_proof(&proof));
}