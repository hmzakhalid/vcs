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

        setupDeployer(); // Moved before setupVerifier
        setupVerifier();

        // Contracts to Deploy
        deployEvenNumber();
        deployLeanBinaryIMT();

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
    function deployLeanBinaryIMT() private {
        LeanBinaryImt binaryIMT = new LeanBinaryImt(verifier);
        console2.log("Deployed LeanBinaryImt to", address(binaryIMT));
    }
}


// // Copyright 2024 RISC Zero, Inc.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
// //

// pragma solidity ^0.8.20;

// import {Script} from "forge-std/Script.sol";
// import "forge-std/Test.sol";
// import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
// import {RiscZeroGroth16Verifier} from "risc0/groth16/RiscZeroGroth16Verifier.sol";
// import {ControlID} from "risc0/groth16/ControlID.sol";

// import {EvenNumber} from "../contracts/EvenNumber.sol";
// contract EvenNumberDeploy is Script {
//     // Path to deployment config file, relative to the project root.
//     string constant CONFIG_FILE = "script/config.toml";

//     IRiscZeroVerifier verifier;

//     function run() external {
//         // Read and log the chainID
//         uint256 chainId = block.chainid;
//         console2.log("You are deploying on ChainID %d", chainId);

//         // Read the config profile from the environment variable, or use the default for the chainId.
//         // Default is the first profile with a matching chainId field.
//         string memory config = vm.readFile(string.concat(vm.projectRoot(), "/", CONFIG_FILE));
//         string memory configProfile = vm.envOr("CONFIG_PROFILE", string(""));
//         if (bytes(configProfile).length == 0) {
//             string[] memory profileKeys = vm.parseTomlKeys(config, ".profile");
//             for (uint256 i = 0; i < profileKeys.length; i++) {
//                 if (stdToml.readUint(config, string.concat(".profile.", profileKeys[i], ".chainId")) == chainId) {
//                     configProfile = profileKeys[i];
//                     break;
//                 }
//             }
//         }

//         if (bytes(configProfile).length != 0) {
//             console2.log("Deploying using config profile:", configProfile);
//             string memory configProfileKey = string.concat(".profile.", configProfile);
//             address riscZeroVerifierAddress =
//                 stdToml.readAddress(config, string.concat(configProfileKey, ".riscZeroVerifierAddress"));
//             // If set, use the predeployed verifier address found in the config.
//             verifier = IRiscZeroVerifier(riscZeroVerifierAddress);
//         }

//         // Determine the wallet to send transactions from.
//         uint256 deployerKey = uint256(vm.envOr("ETH_WALLET_PRIVATE_KEY", bytes32(0)));
//         address deployerAddr = address(0);
//         if (deployerKey != 0) {
//             // Check for conflicts in how the two environment variables are set.
//             address envAddr = vm.envOr("ETH_WALLET_ADDRESS", address(0));
//             require(
//                 envAddr == address(0) || envAddr == vm.addr(deployerKey),
//                 "conflicting settings from ETH_WALLET_PRIVATE_KEY and ETH_WALLET_ADDRESS"
//             );

//             vm.startBroadcast(deployerKey);
//         } else {
//             deployerAddr = vm.envAddress("ETH_WALLET_ADDRESS");
//             vm.startBroadcast(deployerAddr);
//         }

//         // Deploy the verifier, if not already deployed.
//         if (address(verifier) == address(0)) {
//             verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
//             console2.log("Deployed RiscZeroGroth16Verifier to", address(verifier));
//         } else {
//             console2.log("Using IRiscZeroVerifier contract deployed at", address(verifier));
//         }

//         // Deploy the application contract.
//         EvenNumber evenNumber = new EvenNumber(verifier);
//         console2.log("Deployed EvenNumber to", address(evenNumber));

//         vm.stopBroadcast();
//     }
// }
