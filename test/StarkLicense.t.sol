// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StarkLicense.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Mock ERC-20 used as the STARKBOT payment token.
contract MockSTARKBOT is ERC20 {
    constructor() ERC20("STARKBOT", "STARKBOT") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }
}

/// @dev Next-version stub for upgrade tests — just bumps version().
contract StarkLicenseNext is StarkLicense {
    function version() external pure override returns (uint256) {
        return 4;
    }
}

contract StarkLicenseTest is Test {
    StarkLicense public license;
    MockSTARKBOT public token;

    address public deployer = makeAddr("deployer");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    uint256 public constant FEE = 1000e18;
    string public constant URI_1 = "https://example.com/.well-known/agent-registration.json";
    string public constant URI_2 = "ipfs://QmUpdatedAgentURI";
    string public constant URI_3 = "https://agent3.example.com/registration.json";

    function setUp() public {
        token = new MockSTARKBOT();

        StarkLicense impl = new StarkLicense();
        bytes memory initData = abi.encodeCall(StarkLicense.initialize, (address(token), FEE, deployer));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        license = StarkLicense(address(proxy));

        token.mint(alice, 10_000e18);
        token.mint(bob, 10_000e18);
    }

    // ─────────────────── Initialization ───────────────────

    function test_initialize() public view {
        assertEq(license.name(), "STARKBOT Agent License");
        assertEq(license.symbol(), "STARK-LICENSE");
        assertEq(license.owner(), deployer);
        assertEq(license.paymentToken(), address(token));
        assertEq(license.registrationFee(), FEE);
        assertEq(license.totalAgents(), 0);
        assertEq(license.version(), 3);
    }

    function test_initialize_revert_doubleInit() public {
        vm.expectRevert();
        license.initialize(address(token), FEE, deployer);
    }

    function test_initialize_revert_zeroToken() public {
        StarkLicense impl = new StarkLicense();
        vm.expectRevert(IStarkLicense.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(StarkLicense.initialize, (address(0), FEE, deployer)));
    }

    function test_initialize_revert_zeroOwner() public {
        StarkLicense impl = new StarkLicense();
        vm.expectRevert(IStarkLicense.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(StarkLicense.initialize, (address(token), FEE, address(0))));
    }

    function test_implementation_cannotBeInitialized() public {
        StarkLicense impl = new StarkLicense();
        vm.expectRevert();
        impl.initialize(address(token), FEE, deployer);
    }

    // ─────────────────── Registration ───────────────────

    function test_register_withURI() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);

        vm.expectEmit(true, true, false, true);
        emit IStarkLicense.Registered(1, URI_1, alice);

        uint256 agentId = license.register(URI_1);
        vm.stopPrank();

        assertEq(agentId, 1);
        assertEq(license.agentURI(1), URI_1);
        assertEq(license.totalAgents(), 1);
        assertEq(license.ownerOf(1), alice);
        assertEq(token.balanceOf(address(license)), 0);
        assertEq(license.totalBurned(), FEE);
    }

    function test_register_bare() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register();
        vm.stopPrank();

        assertEq(agentId, 1);
        assertEq(license.agentURI(1), "");
        assertEq(token.balanceOf(address(license)), 0);
    }

    function test_register_bare_thenSetURI() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register();
        license.setAgentURI(agentId, URI_1);
        vm.stopPrank();

        assertEq(license.agentURI(agentId), URI_1);
        assertEq(license.tokenURI(agentId), URI_1);
    }

    function test_register_multipleAgentsPerAddress() public {
        vm.startPrank(alice);
        token.approve(address(license), 3 * FEE);

        uint256 id1 = license.register(URI_1);
        uint256 id2 = license.register(URI_2);
        uint256 id3 = license.register(URI_3);
        vm.stopPrank();

        // Each registration mints a new agent
        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(id3, 3);
        assertEq(license.totalAgents(), 3);
        assertEq(license.balanceOf(alice), 3);
        assertEq(token.balanceOf(address(license)), 0);
        assertEq(license.totalBurned(), 3 * FEE);

        // Each has its own URI
        assertEq(license.agentURI(id1), URI_1);
        assertEq(license.agentURI(id2), URI_2);
        assertEq(license.agentURI(id3), URI_3);
    }

    function test_register_twoUsers() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        license.register(URI_1);
        vm.stopPrank();

        vm.startPrank(bob);
        token.approve(address(license), FEE);
        uint256 bobId = license.register(URI_2);
        vm.stopPrank();

        assertEq(bobId, 2);
        assertEq(license.totalAgents(), 2);
        assertEq(token.balanceOf(address(license)), 0);
    }

    function test_register_withMetadata() public {
        IStarkLicense.MetadataEntry[] memory entries = new IStarkLicense.MetadataEntry[](2);
        entries[0] = IStarkLicense.MetadataEntry("name", abi.encode("My Agent"));
        entries[1] = IStarkLicense.MetadataEntry("version", abi.encode("1.0"));

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1, entries);
        vm.stopPrank();

        assertEq(abi.decode(license.getMetadata(agentId, "name"), (string)), "My Agent");
        assertEq(abi.decode(license.getMetadata(agentId, "version"), (string)), "1.0");
    }

    function test_register_revert_insufficientAllowance() public {
        vm.startPrank(alice);
        vm.expectRevert();
        license.register(URI_1);
        vm.stopPrank();
    }

    function test_register_revert_whenPaused() public {
        vm.prank(deployer);
        license.pause();

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        vm.expectRevert();
        license.register(URI_1);
        vm.stopPrank();
    }

    // ─────────────────── URI Updates ───────────────────

    function test_setAgentURI() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        vm.expectEmit(true, true, false, true);
        emit IStarkLicense.URIUpdated(agentId, URI_2, alice);

        license.setAgentURI(agentId, URI_2);
        vm.stopPrank();

        assertEq(license.agentURI(agentId), URI_2);
        assertEq(token.balanceOf(address(license)), 0); // no extra charge
    }

    function test_setAgentURI_revert_notOwner() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IStarkLicense.NotAgentOwner.selector, agentId));
        license.setAgentURI(agentId, URI_2);
    }

    function test_setAgentURI_revert_emptyURI() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);
        vm.expectRevert(IStarkLicense.EmptyURI.selector);
        license.setAgentURI(agentId, "");
        vm.stopPrank();
    }

    // ─────────────────── Metadata ───────────────────

    function test_setMetadata() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        vm.expectEmit(true, false, false, true);
        emit IStarkLicense.MetadataSet(agentId, "description", "description", abi.encode("An awesome agent"));

        license.setMetadata(agentId, "description", abi.encode("An awesome agent"));
        vm.stopPrank();

        assertEq(abi.decode(license.getMetadata(agentId, "description"), (string)), "An awesome agent");
    }

    function test_setMetadata_revert_notOwner() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IStarkLicense.NotAgentOwner.selector, agentId));
        license.setMetadata(agentId, "key", abi.encode("val"));
    }

    // ─────────────────── Wallet Delegation ───────────────────

    function test_setAgentWallet() public {
        (address wallet, uint256 walletPk) = makeAddrAndKey("wallet");

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = license.walletNonce(agentId);

        bytes32 structHash =
            keccak256(abi.encode(license.SET_WALLET_TYPEHASH(), agentId, wallet, nonce, deadline));
        bytes32 digest = _getDigest(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);

        vm.expectEmit(true, true, false, false);
        emit IStarkLicense.AgentWalletSet(agentId, wallet);

        license.setAgentWallet(agentId, wallet, deadline, abi.encodePacked(r, s, v));
        vm.stopPrank();

        assertEq(license.getAgentWallet(agentId), wallet);
        assertEq(license.walletNonce(agentId), 1);
    }

    function test_setAgentWallet_revert_expiredDeadline() public {
        (address wallet, uint256 walletPk) = makeAddrAndKey("wallet");

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        uint256 deadline = block.timestamp - 1;
        bytes32 structHash =
            keccak256(abi.encode(license.SET_WALLET_TYPEHASH(), agentId, wallet, 0, deadline));
        bytes32 digest = _getDigest(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);

        vm.expectRevert(IStarkLicense.DeadlineExpired.selector);
        license.setAgentWallet(agentId, wallet, deadline, abi.encodePacked(r, s, v));
        vm.stopPrank();
    }

    function test_setAgentWallet_revert_badSignature() public {
        (, uint256 wrongPk) = makeAddrAndKey("wrongWallet");
        address wallet = makeAddr("wallet");

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash =
            keccak256(abi.encode(license.SET_WALLET_TYPEHASH(), agentId, wallet, 0, deadline));
        bytes32 digest = _getDigest(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, digest);

        vm.expectRevert(IStarkLicense.InvalidSignature.selector);
        license.setAgentWallet(agentId, wallet, deadline, abi.encodePacked(r, s, v));
        vm.stopPrank();
    }

    function test_unsetAgentWallet() public {
        (address wallet, uint256 walletPk) = makeAddrAndKey("wallet");

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash =
            keccak256(abi.encode(license.SET_WALLET_TYPEHASH(), agentId, wallet, 0, deadline));
        bytes32 digest = _getDigest(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);
        license.setAgentWallet(agentId, wallet, deadline, abi.encodePacked(r, s, v));

        vm.expectEmit(true, false, false, false);
        emit IStarkLicense.AgentWalletUnset(agentId);
        license.unsetAgentWallet(agentId);
        vm.stopPrank();

        assertEq(license.getAgentWallet(agentId), address(0));
    }

    // ─────────────────── Wallet cleared on transfer ───────────────────

    function test_walletClearedOnTransfer() public {
        (address wallet, uint256 walletPk) = makeAddrAndKey("wallet");

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);

        // Set wallet delegation
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash =
            keccak256(abi.encode(license.SET_WALLET_TYPEHASH(), agentId, wallet, 0, deadline));
        bytes32 digest = _getDigest(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletPk, digest);
        license.setAgentWallet(agentId, wallet, deadline, abi.encodePacked(r, s, v));
        assertEq(license.getAgentWallet(agentId), wallet);

        // Transfer to bob — wallet should be cleared
        vm.expectEmit(true, false, false, false);
        emit IStarkLicense.AgentWalletUnset(agentId);
        license.transferFrom(alice, bob, agentId);
        vm.stopPrank();

        assertEq(license.getAgentWallet(agentId), address(0));
    }

    // ─────────────────── ERC-721 / tokenURI / transfers ───────────────────

    function test_tokenURI() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);
        vm.stopPrank();

        assertEq(license.tokenURI(agentId), URI_1);
    }

    function test_transfer() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);
        license.transferFrom(alice, bob, agentId);
        vm.stopPrank();

        assertEq(license.ownerOf(agentId), bob);
        assertEq(license.balanceOf(alice), 0);
        assertEq(license.balanceOf(bob), 1);
    }

    // ─────────────────── EIP-165 ───────────────────

    function test_supportsInterface_ERC721() public view {
        assertTrue(license.supportsInterface(0x80ac58cd));
    }

    function test_supportsInterface_ERC721Enumerable() public view {
        // ERC-721Enumerable = 0x780e9d63
        assertTrue(license.supportsInterface(0x780e9d63));
    }

    function test_supportsInterface_IStarkLicense() public view {
        assertTrue(license.supportsInterface(type(IStarkLicense).interfaceId));
    }

    function test_supportsInterface_ERC165() public view {
        assertTrue(license.supportsInterface(0x01ffc9a7));
    }

    function test_supportsInterface_random_false() public view {
        assertFalse(license.supportsInterface(0xdeadbeef));
    }

    // ─────────────────── Admin ───────────────────

    function test_setRegistrationFee() public {
        uint256 newFee = 500e18;

        vm.expectEmit(false, false, false, true);
        emit IStarkLicense.RegistrationFeeUpdated(FEE, newFee);

        vm.prank(deployer);
        license.setRegistrationFee(newFee);

        assertEq(license.registrationFee(), newFee);
    }

    function test_setRegistrationFee_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert();
        license.setRegistrationFee(1e18);
    }

    function test_pause_unpause() public {
        vm.prank(deployer);
        license.pause();

        vm.startPrank(alice);
        token.approve(address(license), FEE);
        vm.expectRevert();
        license.register(URI_1);
        vm.stopPrank();

        vm.prank(deployer);
        license.unpause();

        vm.startPrank(alice);
        license.register(URI_1);
        vm.stopPrank();

        assertEq(license.totalAgents(), 1);
    }

    // ─────────────────── Upgrades (UUPS) ───────────────────

    function test_upgrade_byOwner() public {
        vm.startPrank(alice);
        token.approve(address(license), FEE);
        uint256 agentId = license.register(URI_1);
        vm.stopPrank();

        assertEq(license.version(), 3);

        StarkLicenseNext v2Impl = new StarkLicenseNext();
        vm.prank(deployer);
        license.upgradeToAndCall(address(v2Impl), "");

        assertEq(license.version(), 4);
        assertEq(license.ownerOf(agentId), alice);
        assertEq(license.agentURI(agentId), URI_1);
        assertEq(license.totalBurned(), FEE);
    }

    function test_upgrade_revert_notOwner() public {
        StarkLicenseNext v2Impl = new StarkLicenseNext();
        vm.prank(alice);
        vm.expectRevert();
        license.upgradeToAndCall(address(v2Impl), "");
    }

    // ─────────────────── Views ───────────────────

    function test_paymentToken() public view {
        assertEq(license.paymentToken(), address(token));
    }

    function test_registrationFee() public view {
        assertEq(license.registrationFee(), FEE);
    }

    function test_totalAgents_matchesTotalSupply() public {
        vm.startPrank(alice);
        token.approve(address(license), 2 * FEE);
        license.register(URI_1);
        license.register(URI_2);
        vm.stopPrank();

        assertEq(license.totalAgents(), 2);
        assertEq(license.totalAgents(), license.totalSupply());
    }

    // ─────────────────── Helpers ───────────────────

    function _getDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("StarkLicense"),
                keccak256("1"),
                block.chainid,
                address(license)
            )
        );
    }
}
