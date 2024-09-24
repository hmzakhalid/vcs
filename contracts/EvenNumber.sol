pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.
import {console} from "forge-std/console.sol";

/// @title A starter application using RISC Zero.
/// @notice This basic application holds a number, guaranteed to be even.
/// @dev This contract demonstrates one pattern for offloading the computation of an expensive
///      or difficult to implement function to a RISC Zero guest running on Bonsai.
contract EvenNumber {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;
    /// @notice Image ID of the only zkVM binary to accept verification from.
    ///         The image ID is similar to the address of a smart contract.
    ///         It uniquely represents the logic of that guest program,
    ///         ensuring that only proofs generated from a pre-defined guest program
    ///         (in this case, checking if a number is even) are considered valid.
    bytes32 public constant imageId = ImageID.IS_EVEN_ID;

    /// @notice A number that is guaranteed, by the RISC Zero zkVM, to be even.
    ///         It can be set by calling the `set` function.
    uint256 public number;

    event Verified(bytes journal);

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
        number = 0;
    }

    /// @notice Set the even number stored on the contract. Requires a RISC Zero proof that the number is even.
    function set(uint256 x, bytes calldata seal) public {
        // Construct the expected journal data. Verify will fail if journal does not match.
        bytes memory journal = abi.encode(x);
        verifier.verify(seal, imageId, sha256(journal));
        number = x;
    }

    function verifyFields(
        bytes32 ctHash,
        bytes32 paramHash,
        bytes32 rootHash,
        bytes calldata seal
    ) public {
        bytes memory journal = new bytes(396); // (32 + 1) * 4 * 3

        encodeLengthPrefixAndHash(journal, 0, ctHash);
        encodeLengthPrefixAndHash(journal, 132, paramHash);
        encodeLengthPrefixAndHash(journal, 264, rootHash);

        verifier.verify(seal, imageId, sha256(journal));
    }

    function encodeLengthPrefixAndHash(bytes memory journal, uint256 startIndex, bytes32 hashVal) internal pure {
        journal[startIndex] = 0x20; // 32 in hex
        startIndex += 4;
        for (uint256 i = 0; i < 32; i++) {
            journal[startIndex + i * 4] = hashVal[i];
        }
    }

    function verify(bytes memory journal, bytes calldata seal) public {
        verifier.verify(seal, imageId, sha256(journal));
    }

    /// @notice Returns the number stored.
    function get() public view returns (uint256) {
        return number;
    }
}
