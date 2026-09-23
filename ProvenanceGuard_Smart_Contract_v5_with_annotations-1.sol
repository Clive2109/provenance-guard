// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Brings in OpenZeppelin libraries
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol"; // NFT standard with metadata storage
import "@openzeppelin/contracts/access/AccessControl.sol"; // Role-based permissions
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol"; // Prevents reentrancy attacks in functions involving payments
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol"; // Meets ERC721 Safe Transfer Requirements



/**
 * @title ProvenanceGuard
 * @dev ERC-721 contract with Fixed Price Escrow and English Auction capabilities.
 * Combines:
 * - NFT-based asset tracking (ERC721)
 * - Provenance history
 * - Escrow marketplace (fixed price)
 * - English auction system
 */
// Inheriting NFT functionality, role-based access, and reentrancy protection

contract ProvenanceGuard is ERC721URIStorage, AccessControl, ReentrancyGuard, IERC721Receiver { //

    /**
    * @dev supportsInterace() ensures the contract properly declares support for both ERC721URIStorage and AccessControl interfaces
    * Required by Solidity, without this override, systems e.g., AccessControl and ERC721 might not correctly recognize the contract’s supported interface
    */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721URIStorage, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // Enabling the contract itself to securely receive NFTs
    function onERC721Received(address, address, uint256, bytes calldata) 
        external pure override returns (bytes4) 
    {
        return IERC721Receiver.onERC721Received.selector;
    }

    // Roles
    bytes32 public constant BRAND_ROLE = keccak256("BRAND_ROLE"); // Can mint and recall assets
    bytes32 public constant INSPECTOR_ROLE = keccak256("INSPECTOR_ROLE"); // Can verify authenticity

    uint256 private _nextTokenId;

    // Type of Asset Listing Status
    enum ListingType { None, FixedPrice, Auction }

    // Asset Struct represents each NFT with metadata, ownership, authenticity, and listing status
    struct Asset {
        uint256 assetID;
        bytes32 serialNumber;
        bytes32 brand;
        string name;
        string metadataHash; // IPFS CID for descriptions/photos
        address currentOwner;
        bool isAuthentic;
        bool isRecalled;
        ListingType listingType;
    }

    mapping(uint256 => Asset) public assets;
    mapping(uint256 => address[]) public ownershipHistory;

    // Mapping of the unique Chip Public Key to the NFT TokenID
    mapping(bytes32 => uint256) public chipToToken;

    // Fixed Price Marketplace

    // Seller lists an item with price, description, and duration
    struct Escrow_Listing {
        uint256 assetID;
        address seller;
        uint256 price;
        string description;
        bool isActive;
        uint256 duration;
    }

    // Buyer initiates purchase, funds held until inspection period ends
    struct Escrow_Transaction {
        uint256 assetID;
        address buyer;
        address seller;
        uint256 agreedPrice;
        uint256 inspectionDeadline; // Timestamp for when the inspection period ends
        bool completed;
        bool disputed;
    }

    // Trade Mappings
    mapping(uint256 => Escrow_Listing) public activeEscrows;
    mapping(uint256 => Escrow_Transaction) public escrowsTransactions;

    // Auction Struct to tracks bids, highest bidder, and auction end time
    struct EnglishAuction {
        uint256 assetID;
        address seller;
        uint256 highestBid;
        address highestBidder;
        uint256 endTime;
        bool active;
    }

    // Auction Mappings
    mapping(uint256 => EnglishAuction) public activeAuctions;

    // Pull-over-Push mechanism for secure refunds (safe withdrawal pattern)
    mapping(address => uint256) public pendingReturns;


    // Events that emit logs for actions
    event AssetMinted(uint256 indexed assetID, address indexed creator, string name);
    event OwnershipTransferred(uint256 indexed assetID, address from, address to);
    event AssetVerified(uint256 indexed assetID, bool status);
    event AssetRecalled(uint256 indexed assetID);

    // Escrow Marketplace
    event ItemListed(uint256 indexed assetID, uint256 price, address indexed seller, string name, uint256 duration);
    event TransactionStarted(uint256 indexed assetID, address indexed buyer, uint256 price, uint256 deadline);
    event TransactionCompleted(uint256 indexed assetID, address indexed buyer, address indexed seller);
    event DisputeRaised(uint256 indexed assetID, address indexed buyer);
    event DisputeResolved(uint256 indexed assetID, address buyer, address seller, bool refundToBuyer, address resolver);
    
    // Auction System
    event AuctionStarted(uint256 indexed assetID, uint256 startingBid, uint256 endTime);
    event BidPlaced(uint256 indexed assetID, address bidder, uint256 amount);
    event AuctionEnded(uint256 indexed assetID, address winner, uint256 amount);


    // Contstructor initializes contract with admin and brand role assigned to deployer
    constructor() ERC721("ProvenanceGuard", "PRVGUARD") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BRAND_ROLE, msg.sender);
    }


    // Asset Functions
    /**
     * @dev Create an Asset - creates NFT linked to chip key, sets metadata, assigns ownership
     * @param chipPublicKey The public key/hash extracted from the secure NFC chip
     */
    function mintAsset(address to, bytes32  serialNumber, bytes32 chipPublicKey, bytes32  brand, string memory name, string memory metadataHash) public onlyRole(BRAND_ROLE) returns (uint256) {

        // Ensure this specific chip hasn't been registered before
        require(chipToToken[chipPublicKey] == 0, "Chip already registered to an asset");

        uint256 assetID = ++_nextTokenId; // If use _nextTokenId++, first assetID = 0 -> conflicts with default mapping value

        // Link the physical hardware key to the digital NFT ID
        chipToToken[chipPublicKey] = assetID;

        _safeMint(to, assetID);
        _setTokenURI(assetID, metadataHash);

        assets[assetID] = Asset({
            assetID: assetID,
            serialNumber: serialNumber,
            brand: brand,
            name: name,
            metadataHash: metadataHash,
            currentOwner: to,
            isAuthentic: true,
            isRecalled: false,
            listingType: ListingType.None
        });

        _addToHistory(assetID, to);
        emit AssetMinted(assetID, to, name);

        return assetID;
    }

    /**
     * @dev Transfer Ownership - Transfers NFT if not recalled
     */
    function transferAsset(address to, uint256 assetID) public {
        require(ownerOf(assetID) != address(0), "Asset does not exist");
        require(ownerOf(assetID) == msg.sender, "Not owner");
        require(!assets[assetID].isRecalled, "Recalled");
        require(assets[assetID].listingType == ListingType.None, "Asset is either listing in the marketplace or auction");

        Escrow_Transaction storage escrow = escrowsTransactions[assetID];
        require(!escrow.disputed && !activeEscrows[assetID].isActive, "Asset in escrow");
        require(!activeAuctions[assetID].active, "Asset in auction");

        _transfer(msg.sender, to, assetID);
        assets[assetID].currentOwner = to;
        _addToHistory(assetID, to);

        emit OwnershipTransferred(assetID, msg.sender, to);
    }

    // Helper function to optimize ownershipHistory
    function _addToHistory(uint256 assetID, address newOwner) internal {
        ownershipHistory[assetID].push(newOwner);
        // Only keep the 10 most recent transactions (gas-friendly)
        if (ownershipHistory[assetID].length > 10) {
            // Remove the oldest record
            for (uint256 i = 0; i < ownershipHistory[assetID].length - 1; i++) {
                ownershipHistory[assetID][i] = ownershipHistory[assetID][i + 1];
            }
            ownershipHistory[assetID].pop();
        }
    }

    /**
     * @dev Verify Authenticity - Inspector marks asset authentic or not
     */
    function verifyAuthenticity(uint256 assetID, bool status) public onlyRole(INSPECTOR_ROLE) {
        assets[assetID].isAuthentic = status;
        emit AssetVerified(assetID, status);
    }

    /**
     * @dev Recall Asset - Brand recalls asset, marking it unauthentic
     */
    function recallAsset(uint256 assetID) public onlyRole(BRAND_ROLE) {
        assets[assetID].isRecalled = true;
        assets[assetID].isAuthentic = false;

        // Automatically remove from the market (if already listed in the marketplace or auction)
        if (assets[assetID].listingType == ListingType.FixedPrice) {

            Escrow_Transaction storage escrow = escrowsTransactions[assetID];
            address s = escrow.seller;
            delete activeEscrows[assetID];
            assets[assetID].listingType = ListingType.None;

            _transfer(address(this), s, assetID);

            if (!escrow.completed && escrow.agreedPrice > 0) {
                escrow.completed = true;
                // refund buyer
                (bool success, ) = payable(escrow.buyer).call{value: escrow.agreedPrice}("");
                require(success, "Refund failed");
            }

        }

        if (assets[assetID].listingType == ListingType.Auction) {

            EnglishAuction storage auction = activeAuctions[assetID];
            address s = auction.seller;
            auction.active = false;
            delete activeAuctions[assetID];
            assets[assetID].listingType = ListingType.None;

            _transfer(address(this), s, assetID);

            if (auction.highestBidder != address(0)) {
                // refund highest bidder
                pendingReturns[auction.highestBidder] += auction.highestBid;
            }

        }

        emit AssetRecalled(assetID);
    }

    /**
     * @dev Intercept all ERC721 transfers (including transferFrom and safeTransferFrom)
     * Only allow them when the device is not in a shelf state or during operations within a contract
     */
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721, ERC721URIStorage)
        returns (address)
    {
        // Determine the sender ('from') address
        address from = _ownerOf(tokenId);

        // Skip the check if this is a mint (from == 0) or a burn (to == 0)
        // Also skip if the contract itself is involved (moving into/out of auction/escrow)
        if (from != address(0) && to != address(0) && to != address(this) && from != address(this)) {
            Escrow_Transaction storage escrow = escrowsTransactions[tokenId];
            
            // Ensure no active market locks
            require(!escrow.disputed && !activeEscrows[tokenId].isActive, "Token in escrow");
            require(!activeAuctions[tokenId].active, "Token in auction");
        }

        // Call the parent implementation to perform the actual transfer logic
        return super._update(to, tokenId, auth);
    }

    // Fixed Price Marketplace
    /**
     * @dev Trade an item in a fixed price
     */

    /**
     * @dev List fixed price item in the marketplace - Owner lists NFT for sale
     */
    function listItem(uint256 assetID, uint256 price, string memory desc, uint256 duration) public {
        require(ownerOf(assetID) != address(0), "Asset does not exist");
        require(ownerOf(assetID) == msg.sender, "Not owner");
        require(duration > 0 && price > 0, "Invalid duration or price");
        require(assets[assetID].listingType == ListingType.None, "Asset already listed");
        require(assets[assetID].isAuthentic && !assets[assetID].isRecalled, "This item is not authentic and has been recalled");

        Escrow_Listing storage list = activeEscrows[assetID];
        if (list.assetID != 0) { // To ensure the transaction record exists
            require(!activeEscrows[assetID].isActive, "Already in an active escrow listing");
        }

        // Escrow_Transaction storage escrow = escrowsTransactions[assetID];
        // if (escrow.assetID != 0) { // To ensure the transaction record exists
        //     require(!escrow.disputed, "Item in dispute");
        // }

        assets[assetID].listingType = ListingType.FixedPrice;
        activeEscrows[assetID] = Escrow_Listing(assetID, msg.sender, price, desc, true, duration);

        _transfer(msg.sender, address(this), assetID);

        emit ItemListed(assetID, price, msg.sender, assets[assetID].name, duration);
    }

    /**
     * @dev Starts a transaction, buyer pays into escrow
     */
    function initiateTransaction(uint256 assetID) public payable nonReentrant {
        Escrow_Listing memory item = activeEscrows[assetID];

        require(ownerOf(assetID) != address(0), "Asset does not exist");
        require(msg.sender != item.seller, "Seller cannot buy their own item");
        require(item.isActive && assets[assetID].listingType == ListingType.FixedPrice, "Asset is not listed for sale");
        require(msg.value > 0 && msg.value == item.price, "Wrong price");

        escrowsTransactions[assetID] = Escrow_Transaction({
            assetID: assetID,
            buyer: msg.sender,
            seller: item.seller,
            // seller: ownerOf(assetID),
            agreedPrice: msg.value,
            inspectionDeadline: block.timestamp + item.duration,
            completed: false,
            disputed: false
        });

        activeEscrows[assetID].isActive = false;

        emit TransactionStarted(assetID, msg.sender, msg.value, escrowsTransactions[assetID].inspectionDeadline);
    }

    /**
     * @dev Buyer confirms, funds released, NFT transferred
     */
    function confirmReceipt(uint256 assetID) public nonReentrant {
        Escrow_Transaction storage escrow = escrowsTransactions[assetID];

        require(escrow.assetID != 0, "No active escrow");
        require(msg.sender == escrow.buyer, "Only buyer can confirm receipt");
        require(!escrow.completed, "Already done");
        require(ownerOf(assetID) == address(this), "Contract does not hold asset");

        // Transfer funds to seller
        (bool success, ) = payable(escrow.seller).call{value: escrow.agreedPrice}("");
        require(success, "Fund transfer failed");
        
        // Transfer NFT to buyer
        _transfer(address(this), escrow.buyer, assetID);

        assets[assetID].currentOwner = escrow.buyer;
        _addToHistory(assetID, escrow.buyer);
        _finalizeFixedPriceSale(assetID);

        escrow.completed = true;

        emit TransactionCompleted(assetID, escrow.buyer, escrow.seller);
    }

    /**
     * @dev Seller claims funds after inspection deadline
     */
    function autoRelease(uint256 assetID) public nonReentrant {
        Escrow_Transaction storage escrow = escrowsTransactions[assetID];

        require(escrow.assetID != 0, "No active escrow");
        require(block.timestamp >= escrow.inspectionDeadline, "Too early, inspection period has not expired yet");
        require(msg.sender == escrow.seller, "Only seller can claim funds");
        require(!escrow.completed, "Already done");
        require(!escrow.disputed, "Item in dispute");
        require(ownerOf(assetID) == address(this), "Contract does not hold asset");

        // Transfer funds to seller
        (bool success, ) = payable(escrow.seller).call{value: escrow.agreedPrice}("");
        require(success, "Fund transfer failed");
        
        // Transfer NFT to buyer
        _transfer(address(this), escrow.buyer, assetID);

        assets[assetID].currentOwner = escrow.buyer;
        _addToHistory(assetID, escrow.buyer);
        _finalizeFixedPriceSale(assetID);

        escrow.completed = true;

        emit TransactionCompleted(assetID, escrow.buyer, escrow.seller);
    }

    // Add an internal helper function to finalize the fixed price transaction
    function _finalizeFixedPriceSale(uint256 assetID) internal {
    
        assets[assetID].listingType = ListingType.None;
        
        delete activeEscrows[assetID];
        delete escrowsTransactions[assetID];

    }

    /**
     * @dev Buyer disputes before deadline
     */
    function raiseDispute(uint256 assetID) public {
        Escrow_Transaction storage escrow = escrowsTransactions[assetID];

        require(msg.sender == escrow.buyer, "Not buyer");
        require(!escrow.completed, "Already completed");
        require(block.timestamp < escrow.inspectionDeadline, "Too late");


        escrow.disputed = true;

        emit DisputeRaised(assetID, escrow.buyer);
    }

    function resolveDispute(uint256 assetID, bool refundToBuyer) public nonReentrant  {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(INSPECTOR_ROLE, msg.sender),
            "Not authorized"
        );

        Escrow_Transaction storage escrow = escrowsTransactions[assetID];
        require(escrow.disputed, "No dispute raised");
        require(!escrow.completed, "Transaction already completed");

        escrow.completed = true;
        assets[assetID].listingType = ListingType.None;

        if (refundToBuyer) {
            // transfer NFT to seller
            require(ownerOf(assetID) == address(this), "Contract does not hold asset");
            _transfer(address(this), escrow.seller, assetID);

            // refund to buyer
            (bool success, ) = payable(escrow.buyer).call{value: escrow.agreedPrice}("");
            require(success, "Refund failed");
        } else {
            // transfer NFT to buyer
            require(ownerOf(assetID) == address(this), "Contract does not hold asset");
            _transfer(address(this), escrow.buyer, assetID);
            assets[assetID].currentOwner = escrow.buyer;
            _addToHistory(assetID, escrow.buyer);

            // refund to seller
            (bool success, ) = payable(escrow.seller).call{value: escrow.agreedPrice}("");
            require(success, "Refund failed");
        }

        delete activeEscrows[assetID];
        delete escrowsTransactions[assetID];

        emit DisputeResolved(assetID, escrow.buyer, escrow.seller, refundToBuyer, msg.sender);

    }

    // English Auction Features
    /**
     * @dev Seller starts an English Auction for a specfic duration.
     */

    /**
     * @dev Seller starts an English auction with specified duration and starting bid
     */
    function startAuction(uint256 assetID, uint256 startingBid, uint256 durationInSeconds) public {
        require(ownerOf(assetID) != address(0), "Asset does not exist");
        require(ownerOf(assetID) == msg.sender, "Only owner can start auction");
        require(durationInSeconds > 0 && startingBid > 0, "Invalid duration or starting bid");
        require(assets[assetID].listingType == ListingType.None, "Asset already listed");
        require(assets[assetID].isAuthentic && !assets[assetID].isRecalled, "This item is not authentic and has been recalled");
        require(!activeAuctions[assetID].active, "Already in auction");

        _transfer(msg.sender, address(this), assetID);
        assets[assetID].listingType = ListingType.Auction;

        activeAuctions[assetID] = EnglishAuction({
            assetID: assetID,
            seller: msg.sender,
            highestBid: startingBid,
            highestBidder: address(0),
            endTime: block.timestamp + durationInSeconds,
            active: true
        });

        emit AuctionStarted(assetID, startingBid, activeAuctions[assetID].endTime);
    }

    /**
     * @dev Users place bids. Funds are held in escrow. Outbid users are refunded.
     */
    function placeBid(uint256 assetID) public payable nonReentrant {
        require(ownerOf(assetID) != address(0), "Asset does not exist");

        EnglishAuction storage auction = activeAuctions[assetID];
        require(auction.active && assets[assetID].listingType == ListingType.Auction, "Auction is not active");
        require(block.timestamp < auction.endTime, "Auction has ended");
        if (auction.highestBidder == address(0)) {
            require(msg.value >= auction.highestBid, "Bid must be at least starting bid");
        } else {
            require(msg.value > auction.highestBid, "Bid must be strictly higher than current highest bid");
        }
        require(msg.sender != auction.seller, "Seller cannot bid on own item");

        // Refund the previous highest bidder via pendingReturns (Pull pattern)
        if (auction.highestBidder != address(0)) {
            //payable(auction.highestBidder).transfer(auction.highestBid);
            pendingReturns[auction.highestBidder] += auction.highestBid;
        }

        // Update auction state
        auction.highestBidder = msg.sender;
        auction.highestBid = msg.value;

        emit BidPlaced(assetID, msg.sender, msg.value);
    }

    /**
     * @dev End the auction, transfer the item, and pay the seller.
     * Anyone can call it after the deadline if the seller forgot to action
     */
    function endAuction(uint256 assetID) public nonReentrant {
        EnglishAuction storage auction = activeAuctions[assetID];

        require(auction.active, "Auction is not active");
        require(block.timestamp >= auction.endTime, "Auction is still ongoing");
        require(ownerOf(assetID) == address(this), "Contract does not hold asset");

        auction.active = false;

        if(auction.highestBidder != address(0)) {

            // Transfer funds to seller
            (bool success, ) = payable(auction.seller).call{value: auction.highestBid}("");
            require(success, "Fund transfer failed");
            
            // Transfer NFT to highest bidder
            _transfer(address(this), auction.highestBidder, assetID);
            assets[assetID].currentOwner = auction.highestBidder;
            _addToHistory(assetID, auction.highestBidder);

            assets[assetID].listingType = ListingType.None;

            delete activeAuctions[assetID];
            emit AuctionEnded(assetID, auction.highestBidder, auction.highestBid);
        } else {
            // No bids were placed; item remains with the seller
             _transfer(address(this), auction.seller, assetID);

            assets[assetID].listingType = ListingType.None;

            delete activeAuctions[assetID];
            emit AuctionEnded(assetID, address(0), 0);
        }
    }

    /**
     * @dev Allows outbid users to withdraw their funds (Pull pattern)
     */
    function withdrawOutbidFunds() public nonReentrant {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No funds to withdraw");

        pendingReturns[msg.sender] = 0;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    /**
     * @dev Seller cancels auction if no bids
     */  
    function cancelAuction(uint256 assetID) public {
        EnglishAuction storage auction = activeAuctions[assetID];

        require(msg.sender == auction.seller, "Not seller");
        require(auction.highestBidder == address(0), "Has bids");

        auction.active = false;
        assets[assetID].listingType = ListingType.None;
        _transfer(address(this), auction.seller, assetID);

        delete activeAuctions[assetID];
    }

    // Role

    /**
     * @dev Assign Inspector - Admin grants inspector role a user
     */  
    function addInspector(address user) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(INSPECTOR_ROLE, user);
    }

    /**
     * @dev Assign Brand Operator - Admin grants brand role a user
     */  
    function addBrand(address user) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(BRAND_ROLE, user);
    }

    /**
     * @dev Query the full provenance/ownership history of an asset
     */
    function queryAssetHistory(uint256 assetID) public view returns (address[] memory) {
        require(ownerOf(assetID) != address(0), "Asset does not exist");
        return ownershipHistory[assetID];
    }

    // View Functions

    /**
     * @dev call getAsset() to retrieve the info of an item but not for
     */
    function getAsset(uint256 assetID) public view returns (
        string memory name,
        string memory metadataHash,
        address currentOwner,
        bool isAuthentic,
        bool isRecalled,
        ListingType listingType,
        bytes32 serialNumber,
        bytes32 brand
    ) {
        Asset memory x = assets[assetID];
        return (
            x.name,
            x.metadataHash,
            x.currentOwner,
            x.isAuthentic,
            x.isRecalled,
            x.listingType,
            x.serialNumber,
            x.brand
        );
    }
}