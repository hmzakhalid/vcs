pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {InternalLeanIMT, LeanIMTData} from "zk-kit.solidity/packages/lean-imt/contracts/InternalLeanIMT.sol"; // Importing IMT contract
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

contract LeanBinaryImt {
    struct E3 {
        uint256 seed;
        uint32[2] threshold;
        uint256[2] startWindow;
        uint256 duration;
        uint256 expiration;
        address e3Program;
        bytes e3ProgramParams;
        address inputValidator;
        address decryptionVerifier;
        bytes32 committeePublicKey;
        bytes32 ciphertextOutput;
        bytes plaintextOutput;
    }

    event E3Activated(
        uint256 e3Id,
        uint256 expiration,
        bytes committeePublicKey
    );

    event InputPublished(
        uint256 indexed e3Id,
        bytes data,
        uint256 inputHash,
        uint256 index
    );

    event PlaintextOutputPublished(uint256 indexed e3Id, bytes plaintextOutput);
    event CiphertextOutputPublished(
        uint256 indexed e3Id,
        bytes ciphertextOutput
    );

    uint256 public nexte3Id = 0; // Counter for E3 IDs
    using InternalLeanIMT for LeanIMTData;
    // Mapping of input merkle trees
    mapping(uint256 e3Id => LeanIMTData imt) public inputs;
    // Mapping of E3 parameters
    mapping(uint256 e3Id => bytes params) public e3Params;
    // Mapping counting the number of inputs for each E3.
    mapping(uint256 e3Id => uint256 inputCount) public inputCounts;

    IRiscZeroVerifier public immutable verifier;
    mapping(uint256 => E3) public e3Polls; // Stores each poll by its e3Id
    bytes32 public constant imageId = bytes32(0x189431209c3cdced4e8a848df6eb641ca7e1a07ebefa434b29017cbfcfd5cb84);
    uint256 public number;

    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
    }

    function getHash(
        bytes memory input
    ) public pure returns (bytes32, uint256) {
        bytes32 keckHash = keccak256(input);
        uint256 inputHash = PoseidonT3.hash([uint256(keckHash), 0]);

        return (keckHash, inputHash);
    }

    function getRoot(uint256 id) public view returns (uint256) {
        return InternalLeanIMT._root(inputs[id]);
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

    // Request a new E3 computation
    function request(
        address filter,
        uint32[2] calldata threshold,
        uint256[2] calldata startWindow,
        uint256 duration,
        address e3Program,
        bytes memory e3ProgramParams,
        bytes memory computeProviderParams
    ) external payable returns (uint256 e3Id, E3 memory e3) {
        nexte3Id++;

        E3 memory newE3 = E3({
            seed: nexte3Id,
            threshold: threshold,
            startWindow: startWindow,
            duration: duration,
            expiration: 0,
            e3Program: e3Program,
            e3ProgramParams: e3ProgramParams,
            inputValidator: address(0),
            decryptionVerifier: address(0),
            committeePublicKey: "",
            ciphertextOutput: "",
            plaintextOutput: ""
        });

        e3Params[nexte3Id] = e3ProgramParams;
        e3Polls[nexte3Id] = newE3;

        return (nexte3Id, newE3);
    }

    // Activate the poll
    function activate(
        uint256 e3Id,
        bytes calldata pubKey
    ) external returns (bool success) {
        require(e3Polls[e3Id].seed > 0, "E3 ID does not exist.");
        require(e3Polls[e3Id].expiration == 0, "Poll already activated.");

        e3Polls[e3Id].expiration = block.timestamp + e3Polls[e3Id].duration;
        e3Polls[e3Id].committeePublicKey = keccak256(pubKey);

        emit E3Activated(e3Id, e3Polls[e3Id].expiration, pubKey);
        return true;
    }

    // Publish input data to the poll
    function publishInput(
        uint256 e3Id,
        bytes memory data
    ) external returns (bool success) {
        require(e3Polls[e3Id].expiration > 0, "Poll not activated.");
        require(
            e3Polls[e3Id].expiration > block.timestamp,
            "Poll has expired."
        );

        uint256 inputHash = PoseidonT3.hash(
            [uint256(keccak256(data)), inputCounts[e3Id]]
        );

        inputCounts[e3Id]++;
        inputs[e3Id]._insert(inputHash);

        emit InputPublished(e3Id, data, inputHash, inputCounts[e3Id] - 1);
        return true;
    }

    // Publish ciphertext output
    function publishCiphertextOutput(
        uint256 e3Id,
        bytes memory ciphertextOutput,
        bytes memory proof
    ) external returns (bool success) {
        bytes32 ciphertextOutputHash = keccak256(ciphertextOutput);
        bytes32 paramshash = keccak256(e3Params[e3Id]);
        bytes32 inputRoot = bytes32(getRoot(e3Id));

        bytes memory journal = new bytes(396); // (32 + 1) * 4 * 3

        encodeLengthPrefixAndHash(journal, 0, ciphertextOutputHash);
        encodeLengthPrefixAndHash(journal, 132, paramshash);
        encodeLengthPrefixAndHash(journal, 264, inputRoot);
        

        verifier.verify(proof, imageId, sha256(journal));
        
        e3Polls[e3Id].ciphertextOutput = ciphertextOutputHash;
        emit CiphertextOutputPublished(e3Id, ciphertextOutput);
        return true;
    }

    // Publish plaintext output
    function publishPlaintextOutput(
        uint256 e3Id,
        bytes memory data
    ) external returns (bool success) {
        E3 storage e3 = e3Polls[e3Id];
        require(e3.expiration <= block.timestamp, "Poll is still ongoing.");
        require(
            e3.ciphertextOutput.length > 0,
            "Ciphertext must be published first."
        );
        require(e3.plaintextOutput.length == 0, "Plaintext already published.");

        e3.plaintextOutput = data;
        emit PlaintextOutputPublished(e3Id, data);
        return true;
    }

    // Retrieve the full E3 poll data by e3Id
    function getE3(uint256 e3Id) external view returns (E3 memory e3) {
        return e3Polls[e3Id];
    }
}
