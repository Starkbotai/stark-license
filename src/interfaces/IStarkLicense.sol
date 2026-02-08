// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IStarkLicense - EIP-8004 Identity Registry for STARKBOT agents
/// @notice Each register() call burns STARKBOT tokens and mints a new agent NFT.
///         A single address can own multiple agents (per EIP-8004).
interface IStarkLicense {
    // ──────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────

    struct MetadataEntry {
        string key;
        bytes value;
    }

    // ──────────────────────────────────────────────
    //  Events (EIP-8004)
    // ──────────────────────────────────────────────

    /// @notice Emitted when a new agent is registered.
    event Registered(uint256 indexed agentId, string agentURI, address indexed owner);

    /// @notice Emitted when an agent's URI is updated (owner only, no payment).
    event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy);

    /// @notice Emitted when metadata is set on an agent.
    event MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue);

    /// @notice Emitted when an agent wallet is set via EIP-712 signature.
    event AgentWalletSet(uint256 indexed agentId, address indexed newWallet);

    /// @notice Emitted when an agent wallet is unset.
    event AgentWalletUnset(uint256 indexed agentId);

    /// @notice Emitted when the registration fee is updated by the owner.
    event RegistrationFeeUpdated(uint256 oldFee, uint256 newFee);

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    error EmptyURI();
    error NotAgentOwner(uint256 agentId);
    error InvalidSignature();
    error DeadlineExpired();
    error ZeroAddress();

    // ──────────────────────────────────────────────
    //  Registration
    // ──────────────────────────────────────────────

    /// @notice Register a new agent (no URI). Burns REGISTRATION_FEE tokens.
    ///         URI can be set later via setAgentURI().
    /// @return agentId The token ID of the new agent.
    function register() external returns (uint256 agentId);

    /// @notice Register a new agent with a URI. Burns REGISTRATION_FEE tokens.
    /// @param agentURI The EIP-8004 agent registration URI.
    /// @return agentId The token ID of the new agent.
    function register(string calldata agentURI) external returns (uint256 agentId);

    /// @notice Register a new agent with URI and initial metadata.
    /// @param agentURI The EIP-8004 agent registration URI.
    /// @param metadata Array of key-value metadata entries.
    /// @return agentId The token ID of the new agent.
    function register(string calldata agentURI, MetadataEntry[] calldata metadata) external returns (uint256 agentId);

    // ──────────────────────────────────────────────
    //  URI & Metadata
    // ──────────────────────────────────────────────

    /// @notice Update the agent URI (owner of the NFT only, no payment required).
    function setAgentURI(uint256 agentId, string calldata newURI) external;

    /// @notice Read a metadata value by key.
    function getMetadata(uint256 agentId, string memory metadataKey) external view returns (bytes memory);

    /// @notice Set a metadata value. Only the agent owner can call this.
    function setMetadata(uint256 agentId, string memory metadataKey, bytes memory metadataValue) external;

    // ──────────────────────────────────────────────
    //  Wallet Delegation (EIP-8004 §wallet)
    // ──────────────────────────────────────────────

    /// @notice Delegate an operational wallet for this agent via EIP-712 signature.
    function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature) external;

    /// @notice Read the delegated wallet for an agent.
    function getAgentWallet(uint256 agentId) external view returns (address);

    /// @notice Remove the delegated wallet.
    function unsetAgentWallet(uint256 agentId) external;

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    /// @notice Get all agent IDs owned by an address.
    function agentsOf(address owner) external view returns (uint256[] memory);

    /// @notice Get the agent URI for a given agent ID.
    function agentURI(uint256 agentId) external view returns (string memory);

    /// @notice Total number of registered agents.
    function totalAgents() external view returns (uint256);

    /// @notice The ERC-20 token required for registration.
    function paymentToken() external view returns (address);

    /// @notice The current registration fee.
    function registrationFee() external view returns (uint256);
}
