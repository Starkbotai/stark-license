// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/StarkLicense.sol";

/// @notice Deploys a new StarkLicense implementation and upgrades the proxy.
/// @dev Usage:
///   source .env
///   PROXY_ADDRESS=0x... forge script script/Upgrade.s.sol --rpc-url $BASE_RPC_URL --broadcast --verify
contract UpgradeStarkLicense is Script {
    function run() external {
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        StarkLicense proxy = StarkLicense(proxyAddress);
        console.log("Proxy:", proxyAddress);
        console.log("Current owner:", proxy.owner());
        console.log("Current version:", proxy.version());
        require(proxy.owner() == deployer, "caller is not owner");

        vm.startBroadcast(deployerKey);

        // 1. Deploy new implementation
        StarkLicense newImpl = new StarkLicense();
        console.log("New implementation deployed at:", address(newImpl));

        // 2. Upgrade proxy to new implementation (no re-initialization needed)
        proxy.upgradeToAndCall(address(newImpl), "");
        console.log("Proxy upgraded. New version:", proxy.version());

        vm.stopBroadcast();

        console.log("");
        console.log("=== UPGRADE COMPLETE ===");
        console.log("Proxy (unchanged):       ", proxyAddress);
        console.log("New implementation:       ", address(newImpl));
    }
}
