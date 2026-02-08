# StarkLicense

**EIP-8004 Identity Registry powered by STARKBOT token burns on Base.**

Each `register()` call burns STARKBOT tokens and mints a new ERC-721 agent identity NFT. A single address can own multiple agents (per EIP-8004). Deployed behind a UUPS proxy (ERC-1967) so the owner can upgrade the implementation.

## Contract Address (Base Mainnet)

| Component | Address |
|-----------|---------|
| Proxy | `0xa23a42D266653846e05d8F356a52298844537472` |
| STARKBOT Token | `0x587Cd533F418825521f3A1daa7CCd1E7339A1B07` |

## How It Works

1. **Approve** 1000 STARKBOT tokens to the proxy address
2. **Call `register()`** (optionally with a URI and/or metadata)
3. The contract **burns** the tokens via `IERC20Burnable.burn()`
4. A new **ERC-721 agent NFT** is minted to your address
5. `Registered(agentId, agentURI, owner)` event is emitted

## Registration Methods

```solidity
// Bare registration (no URI)
function register() external returns (uint256 agentId);

// With URI
function register(string calldata agentURI) external returns (uint256 agentId);

// With URI + initial metadata
function register(string calldata agentURI, MetadataEntry[] calldata metadata) external returns (uint256 agentId);
```

## Agent Lookup

Since the contract inherits ERC721Enumerable, you can look up agents per address:

```solidity
uint256 count = license.balanceOf(owner);
for (uint256 i = 0; i < count; i++) {
    uint256 agentId = license.tokenOfOwnerByIndex(owner, i);
    string memory uri = license.agentURI(agentId);
}
```

## Features

| Feature | Details |
|---------|---------|
| Multi-identity | One address can register multiple agents |
| Token burning | Registration fee is burned, not held |
| Agent URI | Set at registration or update later via `setAgentURI()` |
| Metadata | Arbitrary key-value store per agent (`setMetadata` / `getMetadata`) |
| Wallet delegation | EIP-712 signed delegation via `setAgentWallet()` |
| Transfer safety | Wallet delegation auto-cleared on NFT transfer or burn |
| EIP-165 | Advertises ERC-721, ERC-721Enumerable, and IStarkLicense interfaces |
| Pausable | Owner can pause/unpause registrations |
| Upgradeable | UUPS proxy pattern, owner-authorized upgrades |

## Admin Functions (Owner Only)

- `setRegistrationFee(uint256 newFee)` — Update the burn amount
- `pause()` / `unpause()` — Toggle registration
- `upgradeToAndCall(address, bytes)` — Upgrade implementation

## Development

```shell
forge build        # Compile
forge test         # Run tests
forge test -vvvv   # Verbose test output
```

## Deployment

```shell
# Copy .env.example → .env and fill in PRIVATE_KEY
cp .env.example .env

# Deploy proxy + implementation
source .env && forge script script/Deploy.s.sol:Deploy \
  --rpc-url https://mainnet.base.org --broadcast --verify

# Upgrade existing proxy
source .env && forge script script/Upgrade.s.sol:Upgrade \
  --rpc-url https://mainnet.base.org --broadcast --verify
```

## Version History

| Version | Changes |
|---------|---------|
| V1 | Initial deploy — single agent per address |
| V2 | Multi-identity (ERC721Enumerable), storage-safe upgrade |
| V3 | Actual token burning via `IERC20Burnable`, wallet delegation cleared on transfer |
