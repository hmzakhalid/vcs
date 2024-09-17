pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol";
import {InternalLeanIMT, LeanIMTData} from "zk-kit.solidity/packages/lean-imt/contracts/InternalLeanIMT.sol"; // Importing IMT contract
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

contract LeanBinaryImt {
    using InternalLeanIMT for LeanIMTData;
     // Mapping of input merkle trees
    mapping(uint64 e3Id => LeanIMTData imt) public inputs;

    // Mapping counting the number of inputs for each E3.
    mapping(uint64 e3Id => uint256 inputCount) public inputCounts;

    IRiscZeroVerifier public immutable verifier;
    bytes32 public constant imageId = ImageID.IS_EVEN_ID;
    uint256 public number;

    // emit a number
    event Testing(uint256 e3Id, bytes input);

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
    }

    function displayTree(uint64 id) public view returns (uint256, uint256) {
        return (inputs[id].depth, inputs[id].size);
    }

    function insertLeaf(uint64 id, bytes memory input) public returns (uint256, uint256, uint256) { 
    // Capture the original input count before incrementing
    uint256 originalCount = inputCounts[id];
    
    // Calculate the input hash using the original count
    uint256 inputHash = PoseidonT3.hash([uint256(keccak256(input)), originalCount]);
    
    // Increment the input count for the given id
    inputCounts[id]++;         

    // Insert the new input hash into the merkle tree
    inputs[id]._insert(inputHash);

    // Calculate the current root of the merkle tree
    uint256 currentRoot = InternalLeanIMT._root(inputs[id]);

    // Return inputHash, currentRoot, and the original count used in the hash
    return (inputHash, currentRoot, originalCount);
}


    function getRoot(uint64 id) public view returns (uint256) {
        return InternalLeanIMT._root(inputs[id]);
    }

    function verifyHash(bytes memory input) public pure returns (bytes32) {
        return keccak256(input);
    }
    function verify(bytes32 journalHash, bytes calldata seal) public view {
        verifier.verify(seal, imageId, journalHash);
    }
}
