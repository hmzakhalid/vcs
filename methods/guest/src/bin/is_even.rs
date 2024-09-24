use risc0_zkvm::guest::env;
use vcs_core::{ComputeInput, ComputeResult, fhe_processor};


fn main() {
    let input: ComputeInput = env::read();
    
    let result: ComputeResult = input.process(fhe_processor);

    env::commit(&result);
}
