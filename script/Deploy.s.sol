// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/StarkLicense.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice Deploys StarkLicense implementation + ERC1967 UUPS proxy.
/// @dev Usage:
///   source .env
///   forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast --verify
contract DeployStarkLicense is Script {
    function run() external {
        address starkbotToken = vm.envAddress("STARKBOT_TOKEN");
        uint256 registrationFee = vm.envUint("REGISTRATION_FEE");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        console.log("Deployer:", deployer);
        console.log("STARKBOT token:", starkbotToken);
        console.log("Registration fee:", registrationFee);

        vm.startBroadcast(deployerKey);

        // 1. Deploy implementation (constructor disables initializers)
        StarkLicense impl = new StarkLicense();
        console.log("Implementation deployed at:", address(impl));

        // 2. Deploy proxy and initialize
        bytes memory initData = abi.encodeCall(
            StarkLicense.initialize,
            (starkbotToken, registrationFee, deployer)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        console.log("Proxy deployed at:", address(proxy));

        // 3. Verify initialization
        StarkLicense license = StarkLicense(address(proxy));
        require(license.owner() == deployer, "owner mismatch");
        require(license.paymentToken() == starkbotToken, "token mismatch");
        require(license.registrationFee() == registrationFee, "fee mismatch");
        console.log("Initialization verified. Owner:", license.owner());

        vm.stopBroadcast();

        console.log("");
        console.log("=== DEPLOYMENT COMPLETE ===");
        console.log("Proxy (use this address):", address(proxy));
        console.log("Implementation:          ", address(impl));
    }
}
