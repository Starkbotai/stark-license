// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "./interfaces/IStarkLicense.sol";

/// @dev Minimal interface for ERC-20 tokens that expose a public burn(uint256) function.
interface IERC20Burnable {
    function burn(uint256 amount) external;
}

/// @title StarkLicense — EIP-8004 Identity Registry powered by STARKBOT token burns
/// @notice Each register() call burns STARKBOT tokens and mints a new ERC-721 agent identity.
///         A single address can register multiple agents (per EIP-8004).
///         ERC721Enumerable provides on-chain lookup of all agents owned by an address.
/// @dev Deployed behind an ERC-1967 UUPS proxy. Owner can upgrade via `upgradeToAndCall`.
/// @custom:oz-upgrades
contract StarkLicense is
    IStarkLicense,
    Initializable,
    ERC721Upgradeable,
    ERC721EnumerableUpgradeable,
    EIP712Upgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    // ──────────────────────────────────────────────
    //  Constants & Storage
    // ──────────────────────────────────────────────

    bytes32 public constant SET_WALLET_TYPEHASH =
        keccak256("SetAgentWallet(uint256 agentId,address newWallet,uint256 nonce,uint256 deadline)");

    IERC20 public PAYMENT_TOKEN;
    uint256 public REGISTRATION_FEE;

    uint256 private _nextAgentId;

    /// @dev Deprecated in V2 (was single agent-per-address). Kept for storage layout compatibility.
    mapping(address => uint256) private __deprecated_ownerToAgent;

    /// @dev agentId → agent URI string
    mapping(uint256 => string) private _agentURIs;

    /// @dev agentId → metadata key → value
    mapping(uint256 => mapping(string => bytes)) private _metadata;

    /// @dev agentId → delegated wallet address
    mapping(uint256 => address) private _agentWallets;

    /// @dev agentId → nonce for EIP-712 wallet delegation signatures
    mapping(uint256 => uint256) private _walletNonces;

    /// @dev Total tokens burned (transferred into this contract)
    uint256 public totalBurned;

    // ──────────────────────────────────────────────
    //  Constructor (disables initializers on implementation)
    // ──────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ──────────────────────────────────────────────
    //  Initializer (called once via proxy)
    // ──────────────────────────────────────────────

    /// @notice Initialize the proxy. Called once at deployment.
    /// @param token The STARKBOT ERC-20 token address on Base.
    /// @param fee   The registration fee in token base units (e.g. 1000e18).
    /// @param owner_ The address that will own the contract (can upgrade + admin).
    function initialize(address token, uint256 fee, address owner_) external initializer {
        if (token == address(0)) revert ZeroAddress();
        if (owner_ == address(0)) revert ZeroAddress();

        __ERC721_init("STARKBOT Agent License", "STARK-LICENSE");
        __ERC721Enumerable_init();
        __EIP712_init("StarkLicense", "1");
        __Ownable_init(owner_);
        __Pausable_init();

        PAYMENT_TOKEN = IERC20(token);
        REGISTRATION_FEE = fee;
        _nextAgentId = 1;
    }

    // ──────────────────────────────────────────────
    //  UUPS Upgrade Authorization
    // ──────────────────────────────────────────────

    /// @dev Only the owner can upgrade the implementation.
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ──────────────────────────────────────────────
    //  Registration
    // ──────────────────────────────────────────────

    /// @inheritdoc IStarkLicense
    function register() external whenNotPaused returns (uint256 agentId) {
        return _register(msg.sender, "");
    }

    /// @inheritdoc IStarkLicense
    function register(string calldata uri) external whenNotPaused returns (uint256 agentId) {
        return _register(msg.sender, uri);
    }

    /// @inheritdoc IStarkLicense
    function register(string calldata uri, MetadataEntry[] calldata metadata)
        external
        whenNotPaused
        returns (uint256 agentId)
    {
        agentId = _register(msg.sender, uri);
        for (uint256 i; i < metadata.length; ++i) {
            _setMetadata(agentId, metadata[i].key, metadata[i].value);
        }
    }

    function _register(address caller, string memory uri) internal returns (uint256 agentId) {
        // Pull tokens from caller → this contract, then burn them
        PAYMENT_TOKEN.safeTransferFrom(caller, address(this), REGISTRATION_FEE);
        IERC20Burnable(address(PAYMENT_TOKEN)).burn(REGISTRATION_FEE);
        totalBurned += REGISTRATION_FEE;

        // Always mint a new agent identity
        agentId = _nextAgentId++;
        _mint(caller, agentId);
        _agentURIs[agentId] = uri;

        emit Registered(agentId, uri, caller);
    }

    // ──────────────────────────────────────────────
    //  URI & Metadata
    // ──────────────────────────────────────────────

    /// @inheritdoc IStarkLicense
    function setAgentURI(uint256 agentId, string calldata newURI) external {
        _requireAgentOwner(agentId);
        if (bytes(newURI).length == 0) revert EmptyURI();
        _agentURIs[agentId] = newURI;
        emit URIUpdated(agentId, newURI, msg.sender);
    }

    /// @inheritdoc IStarkLicense
    function getMetadata(uint256 agentId, string memory metadataKey) external view returns (bytes memory) {
        return _metadata[agentId][metadataKey];
    }

    /// @inheritdoc IStarkLicense
    function setMetadata(uint256 agentId, string memory metadataKey, bytes memory metadataValue) external {
        _requireAgentOwner(agentId);
        _setMetadata(agentId, metadataKey, metadataValue);
    }

    function _setMetadata(uint256 agentId, string memory key, bytes memory value) internal {
        _metadata[agentId][key] = value;
        emit MetadataSet(agentId, key, key, value);
    }

    // ──────────────────────────────────────────────
    //  Wallet Delegation (EIP-712)
    // ──────────────────────────────────────────────

    /// @inheritdoc IStarkLicense
    function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature) external {
        _requireAgentOwner(agentId);
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (newWallet == address(0)) revert ZeroAddress();

        uint256 nonce = _walletNonces[agentId]++;

        bytes32 structHash = keccak256(abi.encode(SET_WALLET_TYPEHASH, agentId, newWallet, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);

        bool valid = SignatureChecker.isValidSignatureNow(newWallet, digest, signature);
        if (!valid) revert InvalidSignature();

        _agentWallets[agentId] = newWallet;
        emit AgentWalletSet(agentId, newWallet);
    }

    /// @inheritdoc IStarkLicense
    function getAgentWallet(uint256 agentId) external view returns (address) {
        return _agentWallets[agentId];
    }

    /// @inheritdoc IStarkLicense
    function unsetAgentWallet(uint256 agentId) external {
        _requireAgentOwner(agentId);
        delete _agentWallets[agentId];
        emit AgentWalletUnset(agentId);
    }

    /// @notice Current nonce for EIP-712 wallet delegation.
    function walletNonce(uint256 agentId) external view returns (uint256) {
        return _walletNonces[agentId];
    }

    // ──────────────────────────────────────────────
    //  ERC-165 / ERC-721 Overrides
    // ──────────────────────────────────────────────

    /// @notice EIP-165: advertise ERC-721 + ERC-721Enumerable + IStarkLicense.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        return interfaceId == type(IStarkLicense).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @notice Returns the agent URI as the token URI (EIP-8004 alignment).
    function tokenURI(uint256 agentId) public view override returns (string memory) {
        _requireOwned(agentId);
        return _agentURIs[agentId];
    }

    /// @dev Required override for ERC721 + ERC721Enumerable.
    ///      Clears wallet delegation on transfer/burn so stale delegations don't persist.
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (address)
    {
        address from = super._update(to, tokenId, auth);
        // Clear wallet delegation on transfer or burn (not on mint)
        if (from != address(0) && _agentWallets[tokenId] != address(0)) {
            delete _agentWallets[tokenId];
            emit AgentWalletUnset(tokenId);
        }
        return from;
    }

    /// @dev Required override for ERC721 + ERC721Enumerable.
    function _increaseBalance(address account, uint128 value)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
    {
        super._increaseBalance(account, value);
    }

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    /// @inheritdoc IStarkLicense
    function agentURI(uint256 agentId) external view returns (string memory) {
        return _agentURIs[agentId];
    }

    /// @inheritdoc IStarkLicense
    function totalAgents() external view returns (uint256) {
        return totalSupply();
    }

    /// @inheritdoc IStarkLicense
    function paymentToken() external view returns (address) {
        return address(PAYMENT_TOKEN);
    }

    /// @inheritdoc IStarkLicense
    function registrationFee() external view returns (uint256) {
        return REGISTRATION_FEE;
    }

    /// @notice Returns the implementation version. Bump on each upgrade.
    function version() external pure virtual returns (uint256) {
        return 3;
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Update the registration fee. Only contract owner.
    function setRegistrationFee(uint256 newFee) external onlyOwner {
        uint256 oldFee = REGISTRATION_FEE;
        REGISTRATION_FEE = newFee;
        emit RegistrationFeeUpdated(oldFee, newFee);
    }

    /// @notice Pause registrations.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause registrations.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ──────────────────────────────────────────────
    //  Internals
    // ──────────────────────────────────────────────

    function _requireAgentOwner(uint256 agentId) internal view {
        if (ownerOf(agentId) != msg.sender) revert NotAgentOwner(agentId);
    }
}
