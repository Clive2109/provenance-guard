# 🛡️ ProvenanceGuard: Decentralized Luxury Authentication & Marketplace

An enter anti-counterfeiting Web3 protocol built on the **Polygon blockchain** designed to secure physical luxury assets using tamper-proof digital twins (**ERC-721 NFTs**).

---

# 💡 The Problem & Business Case
*   **The Problem:** The global counterfeit luxury market is valued at over $4.5 Trillion, eroding brand trust, hurting legitimate revenues, and exposing secondary-market buyers to high-stakes fraud.
*   **The Solution:** **ProvenanceGuard** links physical luxury items to unique digital certificates of authenticity on-chain. By mapping hardware keys to NFTs, brands can guarantee product origins, manage recalls, and secure secondary market transactions.

---

## 🛠️ Technical Features & Smart Contract Architecture

### 1. NFC Chip-to-NFT Mapping (`chipToToken`)
- Maps the unique public key hash of a secure physical NFC chip embedded in a luxury item directly to its digital NFT counterpart at the moment of minting.
- Prevents the physical item from being separated or swapped from its digital certificate of authenticity.

### 2. Built-in Escrow Marketplace (Fixed Price)
- Sellers list luxury goods for a fixed price with a set inspection duration.
- Buyers initiate a transaction by locking funds into the contract's escrow state.
- Supports manual receipt confirmation or automatic seller fund release after the inspection deadline, with an integrated dispute resolution mechanism handled by authorized `INSPECTOR_ROLE` users.

### 3. Decentralized English Auction System
- Sellers can launch bidding wars with a minimum starting bid and a specific duration.
- Utilizes a secure **pull-over-push payment pattern** (`withdrawOutbidFunds`) to protect outbid users and eliminate potential Denial of Service (DoS) and reentrancy attacks.

### 4. Enterprise-Grade Access Control
Utilizes OpenZeppelin's `AccessControl` for strict role separation:
*   `BRAND_ROLE`: Can mint new assets and trigger product recalls (which instantly halts market actions).
*   `INSPECTOR_ROLE`: Verifies physical asset authenticity and arbitrates escrow disputes.
*   `DEFAULT_ADMIN_ROLE`: Configures system operators and roles.

---

## 🔐 Web3 Security Protocols
*   **Reentrancy Guard:** Protected with OpenZeppelin's `ReentrancyGuard` on all state-changing payment functions (`initiateTransaction`, `confirmReceipt`, `autoRelease`, `placeBid`, and `endAuction`).
*   **Safe Transfer Checks:** Inherits standard `ERC721URIStorage` and `IERC721Receiver` requirements to guarantee safe ERC-721 token transfers.
*   **State Locking:** Intercepts transfer requests using internal override `_update()` to prevent ownership manipulation while an asset is actively listed in escrow or an auction.

---

## 💻 Tech Stack
- **Smart Contract Language:** Solidity `^0.8.20`
- **Security Libraries:** OpenZeppelin Core Contracts (`ERC721URIStorage`, `AccessControl`, `ReentrancyGuard`)
- **Storage Layer:** IPFS (Decentralized storage for asset descriptions, media metadata, and provenance data)
- **Deployment Platform:** Polygon (Amoy Testnet / Mainnet)
