pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol";

contract EvenNumber {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public constant imageId = ImageID.IS_EVEN_ID;
    uint256 public number;

    // emit a number
    event Testing(uint256 e3Id, bytes input);

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
        number = 0;
    }

    function set(uint256 x, bytes calldata seal) public {
        bytes memory journal = abi.encode(x);
        verifier.verify(seal, imageId, sha256(journal));
        number = x;
    }

    function emitData(uint256 x, bytes memory data ) public {
        emit Testing(x, data);
    }

    function get() public view returns (uint256) {
        return number;
    }
}

