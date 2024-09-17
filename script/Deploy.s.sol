// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
import {ControlID} from "risc0/groth16/ControlID.sol";

import {EvenNumber} from "../contracts/EvenNumber.sol";
import {LeanBinaryImt} from "../contracts/LeanBinaryImt.sol";

contract DeploymentScript is Script {
    string constant CONFIG_FILE = "script/config.toml";
    IRiscZeroVerifier public verifier;

    function run() external {
        uint256 chainId = block.chainid;
        console2.log("Deploying on ChainID %d", chainId);

        setupVerifier();
        setupDeployer();

        // Contracts to Deploy
        deployEvenNumber();
        deployLeanBinaryImt();

        vm.stopBroadcast();
    }

    function setupVerifier() private {
        string memory config = vm.readFile(string.concat(vm.projectRoot(), "/", CONFIG_FILE));
        string memory configProfile = getConfigProfile(config);

        if (bytes(configProfile).length != 0) {
            console2.log("Using config profile:", configProfile);
            address riscZeroVerifierAddress = stdToml.readAddress(
                config,
                string.concat(".profile.", configProfile, ".riscZeroVerifierAddress")
            );
            verifier = IRiscZeroVerifier(riscZeroVerifierAddress);
        }

        if (address(verifier) == address(0)) {
            verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
            console2.log("Deployed RiscZeroGroth16Verifier to", address(verifier));
        } else {
            console2.log("Using IRiscZeroVerifier at", address(verifier));
        }
    }

    function setupDeployer() private {
        uint256 deployerKey = uint256(vm.envOr("ETH_WALLET_PRIVATE_KEY", bytes32(0)));
        address deployerAddr = vm.envOr("ETH_WALLET_ADDRESS", address(0));

        if (deployerKey != 0) {
            require(
                deployerAddr == address(0) || deployerAddr == vm.addr(deployerKey),
                "Conflicting wallet settings"
            );
            vm.startBroadcast(deployerKey);
        } else {
            require(deployerAddr != address(0), "No deployer address set");
            vm.startBroadcast(deployerAddr);
        }
    }

    function getConfigProfile(string memory config) private view returns (string memory) {
        string memory configProfile = vm.envOr("CONFIG_PROFILE", string(""));
        if (bytes(configProfile).length == 0) {
            string[] memory profileKeys = vm.parseTomlKeys(config, ".profile");
            for (uint256 i = 0; i < profileKeys.length; i++) {
                if (stdToml.readUint(config, string.concat(".profile.", profileKeys[i], ".chainId")) == block.chainid) {
                    return profileKeys[i];
                }
            }
        }
        return configProfile;
    }

    function deployEvenNumber() private {
        EvenNumber evenNumber = new EvenNumber(verifier);
        console2.log("Deployed EvenNumber to", address(evenNumber));
    }

    function deployLeanBinaryImt() private {
        LeanBinaryImt leanBinaryImt = new LeanBinaryImt(verifier);
        console2.log("Deployed LeanBinaryImt to", address(leanBinaryImt));
    }
}