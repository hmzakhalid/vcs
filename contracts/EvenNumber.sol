pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol";
import "imt/BinaryIMT.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

contract EvenNumber {
    using BinaryIMT for BinaryIMTData;
    BinaryIMTData public tree;

    IRiscZeroVerifier public immutable verifier;
    bytes32 public constant imageId = ImageID.IS_EVEN_ID;
    uint256 public number;

    // emit a number
    event Testing(uint256 e3Id, bytes input);

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
        number = 0;
        BinaryIMT.initWithDefaultZeroes(tree, 32);
    }

    function insertLeaf(bytes memory input) public returns (uint256, uint256) {
        uint256 inputHash = PoseidonT3.hash([uint256(keccak256(input)), 0]);         
        BinaryIMT.insert(tree, inputHash);
        uint256 currentRoot = tree.root;
        return (inputHash, currentRoot);
    }

    function getRoot() public view returns (uint256) {
        return tree.root;
    }

    function verifyHash(bytes memory input) public pure returns (bytes32) {
        return keccak256(input);
    }

    function set(uint256 x, bytes calldata seal) public {
        bytes memory journal = abi.encode(x);
        verifier.verify(seal, imageId, sha256(journal));
        number = x;
    }

    function emitData(uint256 x, bytes memory data) public {
        emit Testing(x, data);
    }

    function get() public view returns (uint256) {
        return number;
    }
}
