// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IUSDTPolicy} from "./IUSDTPolicy.sol";

/// @title USDOM reserve with delayed, rate-limited quorum withdrawals
/// @notice Security candidate, not audited. A quorum attests FINALIZED DOM burns;
/// this contract does not verify DOM consensus, note proofs, or issuance itself.
/// No upgrade, arbitrary call, collateral sweep, deposit refund, or supply mint.
/// All amounts are integer token base units (six decimals).
contract USDOMReserve is EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public constant ETHEREUM_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    uint256 public constant MAX_NOTARIES = 16;
    uint256 public constant REFILL_PERIOD = 1 days;
    uint256 public constant MAX_CERTIFICATE_LIFETIME = 7 days;
    uint256 public constant MIN_EXECUTION_WINDOW = 1 hours;
    uint256 public constant BN254_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 public constant MAX_PRUNE_BATCH = 256;
    bytes32 public constant BURN_TYPEHASH = keccak256(
        "Burn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,uint64 epoch,uint64 validUntil)"
    );

    IERC20 public immutable token;
    bytes32 public immutable domDomain;
    address public immutable governance;
    address public immutable guardian;
    uint64 public immutable withdrawalDelay;
    uint64 public immutable governanceDelay;
    uint64 public immutable maxOutstanding;
    uint64 public immutable outflowCapacity;

    struct Config {
        IERC20 token;
        bytes32 domDomain;
        address governance;
        address guardian;
        uint64 withdrawalDelay;
        uint64 governanceDelay;
        uint64 maxOutstanding;
        uint64 outflowCapacity;
    }

    struct Deposit {
        address funder;
        uint64 amount;
        bytes32 receivingCommitment;
    }

    struct Burn {
        bytes32 burnId;
        bytes32 requestId;
        address recipient;
        uint64 amount;
        bytes32 domDomain;
        uint64 height;
        bytes32 blockHash;
        uint64 epoch;
        uint64 validUntil;
    }

    struct PendingWithdrawal {
        bytes32 digest;
        bytes32 requestId;
        uint64 readyAt;
        uint64 expiresAt;
        uint64 epoch;
        uint64 amount;
        bytes32 previous;
        bytes32 next;
    }

    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => bool) public paidBurns;
    mapping(bytes32 => bool) public paidRequests;
    mapping(bytes32 => PendingWithdrawal) public pendingWithdrawals;
    mapping(bytes32 => bytes32) public pendingRequests;
    mapping(address => uint64) public notaryEpoch;
    /// @notice Emergency revocation is permanent; ordinary rotation does not revoke keys.
    mapping(address => bool) public revokedNotary;
    address[] private activeNotarySet;
    bytes32 public currentConfigHash;
    uint64 public currentEpoch;
    uint8 public threshold;
    uint8 public notaryCount;
    uint256 public totalDeposited;
    uint256 public totalReleased;
    /// @notice Current-epoch collateral reserved by accepted certificates.
    uint256 public totalPendingAmount;
    uint256 public pendingCount;
    bytes32 public firstPendingBurn;
    bytes32 public lastPendingBurn;

    bool public paused;
    bool public recoveryRequired;
    uint64 public recoveryEpoch;
    uint64 public resumeReadyAt;
    uint64 public resumeEpoch;
    bytes32 public resumeConfigHash;
    bytes32 public proposedNotariesHash;
    uint64 public notariesReadyAt;
    uint64 private bucketBalance;
    uint64 private bucketUpdatedAt;

    event Deposited(bytes32 indexed id, address indexed funder, uint64 amount, bytes32 receivingCommitment);
    event WithdrawalQueued(
        bytes32 indexed burnId, bytes32 indexed requestId, bytes32 digest, uint64 readyAt, uint64 expiresAt
    );
    /// @notice Complete public certificate, including contract-relayed submissions.
    event WithdrawalCertificate(bytes32 indexed burnId, Burn certificate);
    event Released(
        bytes32 indexed burnId,
        bytes32 indexed requestId,
        address indexed recipient,
        uint64 amount,
        uint64 height,
        bytes32 blockHash,
        uint64 epoch
    );
    event WithdrawalDiscarded(bytes32 indexed burnId, bytes32 indexed requestId);
    event Paused(address indexed caller);
    event RecoveryStarted(uint64 indexed epoch);
    event NotaryRevoked(address indexed notary);
    event ResumeScheduled(uint64 readyAt, uint64 epoch, bytes32 configurationHash);
    event Resumed();
    event NotariesProposed(bytes32 indexed configurationHash, address[] signers, uint8 threshold, uint64 readyAt);
    event NotariesProposalCancelled(bytes32 indexed configurationHash);
    event NotariesInstalled(uint64 indexed epoch, address[] signers, uint8 threshold);

    error InvalidConfiguration();
    error Unauthorized();
    error IsPaused();
    error NotPaused();
    error InvalidDeposit();
    error InvalidBurn();
    error AlreadyUsed();
    error InvalidQuorum();
    error InvalidCertificateWindow();
    error PendingMismatch();
    error TooEarly();
    error StaleCertificate();
    error StillValid();
    error UnsupportedToken();
    error PrototypeOnly();
    error Insolvent();
    error ExposureLimit();
    error OutflowLimit();
    error NoProposal();
    error RecoveryRequired();
    error RotationPending();
    error RevokedNotary();
    error StaleResume();
    error StaleEmergency();
    error TimestampOverflow();
    error UnsafeTokenState();
    error FrozenTokenAccount(address account);

    modifier onlyGovernance() {
        if (msg.sender != governance) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    constructor(Config memory config, address[] memory signers, uint8 threshold_) EIP712("USDOMReserve", "3") {
        // Operator requirement: quorum is prototype-only. Production needs DOM proofs.
        if (block.chainid == 1) revert PrototypeOnly();
        if (
            address(config.token).code.length == 0 || config.domDomain == bytes32(0)
                || config.governance.code.length == 0 || config.guardian.code.length == 0
                || config.guardian == config.governance || config.governance == address(config.token)
                || config.guardian == address(config.token) || config.withdrawalDelay < 6 hours
                || config.withdrawalDelay > 3 days || config.governanceDelay < 2 days
                || config.governanceDelay > 30 days || config.maxOutstanding == 0 || config.outflowCapacity == 0
                || config.outflowCapacity > config.maxOutstanding
        ) revert InvalidConfiguration();
        if (IERC20Metadata(address(config.token)).decimals() != 6) revert UnsupportedToken();
        token = config.token;
        domDomain = config.domDomain;
        governance = config.governance;
        guardian = config.guardian;
        withdrawalDelay = config.withdrawalDelay;
        governanceDelay = config.governanceDelay;
        maxOutstanding = config.maxOutstanding;
        outflowCapacity = config.outflowCapacity;
        bucketBalance = config.outflowCapacity;
        bucketUpdatedAt = _checkedUint64(block.timestamp);
        _requireTokenUsable(address(this), address(this));
        _validateNotaries(signers, threshold_);
        _installNotaries(signers, threshold_);
    }

    /// @notice Credited deposits minus completed payouts; donations are not issuance credits.
    /// This is NOT a measurement of USDOM circulating on the other blockchain.
    function outstanding() public view returns (uint256) {
        return totalDeposited - totalReleased;
    }

    function depositId(address funder, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), funder, salt));
    }

    /// @notice Unreserved credit, not a measurement of remote circulating supply.
    function unreservedCollateral() public view returns (uint256) {
        return outstanding() - totalPendingAmount;
    }

    /// @notice Minimum certificate delay and unreserved collateral only.
    /// The shared rate limit, pauses or token behavior can postpone execution.
    function previewWithdrawal(uint64 amount) external view returns (uint64 readyAt, uint256 availableCredit) {
        if (amount == 0) revert InvalidBurn();
        if (amount > outflowCapacity) revert OutflowLimit();
        return (_timestampAfter(withdrawalDelay), unreservedCollateral());
    }

    function deposit(uint64 amount, bytes32 salt, bytes32 receivingCommitment)
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 id)
    {
        if (amount == 0 || receivingCommitment == bytes32(0) || uint256(receivingCommitment) >= BN254_SCALAR_FIELD) revert InvalidDeposit();
        _requireTokenUsable(msg.sender, address(this));
        if (outstanding() + amount > maxOutstanding) revert ExposureLimit();
        id = depositId(msg.sender, salt);
        if (deposits[id].funder != address(0)) revert AlreadyUsed();
        uint256 reserveBefore = token.balanceOf(address(this));
        if (reserveBefore < outstanding()) revert Insolvent();
        uint256 funderBefore = token.balanceOf(msg.sender);
        deposits[id] = Deposit(msg.sender, amount, receivingCommitment);
        totalDeposited += amount;
        token.safeTransferFrom(msg.sender, address(this), amount);
        if (
            token.balanceOf(address(this)) != reserveBefore + amount
                || token.balanceOf(msg.sender) + amount != funderBefore
        ) revert UnsupportedToken();
        emit Deposited(id, msg.sender, amount, receivingCommitment);
    }

    function burnDigest(Burn calldata burn) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(BURN_TYPEHASH, burn)));
    }

    /// @notice Permissionless relay. The signed recipient can never be replaced by the relayer.
    /// A queued certificate still needs its waiting period, current epoch, and unexpired deadline.
    function queueWithdrawal(Burn calldata burn, bytes[] calldata signatures) external nonReentrant whenNotPaused {
        if (
            burn.burnId == bytes32(0) || burn.requestId == bytes32(0) || burn.recipient == address(0)
                || burn.recipient == address(this) || burn.recipient == address(token) || burn.amount == 0
                || burn.domDomain != domDomain || burn.height == 0 || burn.blockHash == bytes32(0)
        ) revert InvalidBurn();
        _requireTokenUsable(address(this), burn.recipient);
        if (burn.epoch != currentEpoch) revert StaleCertificate();
        if (burn.amount > outflowCapacity) revert OutflowLimit();
        uint64 readyAt = _timestampAfter(withdrawalDelay);
        uint64 latestExpiry = _timestampAfter(MAX_CERTIFICATE_LIFETIME);
        if (burn.validUntil < uint256(readyAt) + MIN_EXECUTION_WINDOW || burn.validUntil > latestExpiry) {
            revert InvalidCertificateWindow();
        }
        if (burn.amount > unreservedCollateral() || token.balanceOf(address(this)) < outstanding()) revert Insolvent();
        if (
            paidBurns[burn.burnId] || paidRequests[burn.requestId]
                || pendingWithdrawals[burn.burnId].digest != bytes32(0) || pendingRequests[burn.requestId] != bytes32(0)
        ) revert AlreadyUsed();
        if (signatures.length != threshold) revert InvalidQuorum();
        bytes32 digest = burnDigest(burn);
        address previous = address(0);
        for (uint256 i; i < signatures.length; ++i) {
            address signer = ECDSA.recover(digest, signatures[i]);
            if (notaryEpoch[signer] != currentEpoch || signer <= previous) revert InvalidQuorum();
            previous = signer;
        }
        pendingWithdrawals[burn.burnId] = PendingWithdrawal(
            digest, burn.requestId, readyAt, burn.validUntil, currentEpoch, burn.amount, lastPendingBurn, bytes32(0)
        );
        if (lastPendingBurn == bytes32(0)) firstPendingBurn = burn.burnId;
        else pendingWithdrawals[lastPendingBurn].next = burn.burnId;
        lastPendingBurn = burn.burnId;
        ++pendingCount;
        totalPendingAmount += burn.amount;
        pendingRequests[burn.requestId] = burn.burnId;
        emit WithdrawalQueued(burn.burnId, burn.requestId, digest, readyAt, burn.validUntil);
        emit WithdrawalCertificate(burn.burnId, burn);
    }

    /// @notice Execute the exact queued certificate. Transfer failure rolls back ALL state.
    function executeWithdrawal(Burn calldata burn) external nonReentrant whenNotPaused {
        PendingWithdrawal memory pending = pendingWithdrawals[burn.burnId];
        if (pending.digest == bytes32(0) || pending.digest != burnDigest(burn)) revert PendingMismatch();
        // Ethereum timestamps are the protocol clock. The configured delay is
        // at least six hours, far above the bounded proposer timestamp skew.
        // forge-lint: disable-next-line(block-timestamp)
        if (pending.epoch != currentEpoch || block.timestamp > pending.expiresAt) revert StaleCertificate();
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < pending.readyAt) revert TooEarly();
        _requireTokenUsable(address(this), burn.recipient);
        uint256 credited = outstanding();
        if (burn.amount > credited) revert Insolvent();
        uint256 available = availableOutflow();
        if (burn.amount > available) revert OutflowLimit();
        uint256 reserveBefore = token.balanceOf(address(this));
        if (reserveBefore < credited) revert Insolvent();
        uint256 recipientBefore = token.balanceOf(burn.recipient);

        // available <= outflowCapacity (uint64), and amount <= available.
        bucketBalance = _checkedUint64(available - burn.amount);
        bucketUpdatedAt = _checkedUint64(block.timestamp);
        totalReleased += burn.amount;
        paidBurns[burn.burnId] = true;
        paidRequests[burn.requestId] = true;
        _removePending(burn.burnId, pending);

        token.safeTransfer(burn.recipient, burn.amount);
        if (
            token.balanceOf(address(this)) + burn.amount != reserveBefore
                || token.balanceOf(burn.recipient) != recipientBefore + burn.amount
        ) revert UnsupportedToken();
        emit Released(burn.burnId, burn.requestId, burn.recipient, burn.amount, burn.height, burn.blockHash, burn.epoch);
    }

    /// @notice Expired/revoked certificates can be removed; the same real burn may be
    /// attested again with fresh current-epoch signatures. Paid IDs can NEVER be cleared.
    function discardWithdrawal(bytes32 burnId) external nonReentrant {
        PendingWithdrawal memory pending = pendingWithdrawals[burnId];
        if (pending.digest == bytes32(0)) revert PendingMismatch();
        // forge-lint: disable-next-line(block-timestamp)
        if (pending.epoch == currentEpoch && block.timestamp <= pending.expiresAt) revert StillValid();
        _removePending(burnId, pending);
        emit WithdrawalDiscarded(burnId, pending.requestId);
    }

    /// @notice Bounded housekeeping. Never removes an unexpired current-epoch head.
    function pruneExpired(uint256 maximum) external nonReentrant returns (uint256 removed) {
        if (maximum == 0 || maximum > MAX_PRUNE_BATCH) revert InvalidConfiguration();
        while (removed < maximum && firstPendingBurn != bytes32(0)) {
            bytes32 burnId = firstPendingBurn;
            PendingWithdrawal memory pending = pendingWithdrawals[burnId];
            // forge-lint: disable-next-line(block-timestamp)
            if (block.timestamp <= pending.expiresAt) break;
            _removePending(burnId, pending);
            emit WithdrawalDiscarded(burnId, pending.requestId);
            ++removed;
        }
    }

    function _removePending(bytes32 burnId, PendingWithdrawal memory pending) private {
        // Rotation invalidates the entire old queue in O(1). Lazy cleanup of an old
        // certificate must never change the new queue's links or reserved credit.
        if (pending.epoch == currentEpoch) {
            if (pending.previous == bytes32(0)) firstPendingBurn = pending.next;
            else pendingWithdrawals[pending.previous].next = pending.next;
            if (pending.next == bytes32(0)) lastPendingBurn = pending.previous;
            else pendingWithdrawals[pending.next].previous = pending.previous;
            totalPendingAmount -= pending.amount;
            --pendingCount;
        }
        delete pendingRequests[pending.requestId];
        delete pendingWithdrawals[burnId];
    }

    /// @notice Token bucket: burst up to capacity, then capacity/24h refill, capped at capacity.
    /// Integer rounding is conservative. This is not a fixed calendar-day limit.
    function availableOutflow() public view returns (uint256) {
        uint256 elapsed = block.timestamp - bucketUpdatedAt;
        if (elapsed >= REFILL_PERIOD) return outflowCapacity;
        uint256 available = bucketBalance + elapsed * outflowCapacity / REFILL_PERIOD;
        return available > outflowCapacity ? outflowCapacity : available;
    }

    /// @notice Refill time for this amount assuming no intervening payout. This is NOT
    /// a reservation, a payout deadline, or a check of certificate/solvency/paused state.
    function secondsUntilOutflow(uint64 amount) external view returns (uint256) {
        if (amount == 0) revert InvalidBurn();
        if (amount > outflowCapacity) revert OutflowLimit();
        if (amount <= availableOutflow()) return 0;
        uint256 required = (uint256(amount) - bucketBalance) * REFILL_PERIOD;
        uint256 accrued = (block.timestamp - bucketUpdatedAt) * outflowCapacity;
        return (required - accrued + outflowCapacity - 1) / outflowCapacity;
    }

    /// @notice Emergency stop for suspected key compromise. Permanently revokes EVERY
    /// active notary and requires fresh keys, installation, then a NEW resume delay.
    /// The guardian/governance can censor; there is intentionally no un-revoke function.
    function pause() external {
        _pauseEmergency();
    }

    /// @notice Monitor stop bound to the observed generation. A pending transaction
    /// cannot revoke replacement keys if rotation wins transaction ordering.
    function pauseEpoch(uint64 expectedEpoch) external {
        if (expectedEpoch != currentEpoch) revert StaleEmergency();
        _pauseEmergency();
    }

    function _pauseEmergency() private {
        if (msg.sender != guardian && msg.sender != governance) revert Unauthorized();
        paused = true;
        recoveryRequired = true;
        recoveryEpoch = currentEpoch;
        _clearResume();
        for (uint256 i; i < activeNotarySet.length; ++i) {
            address signer = activeNotarySet[i];
            if (!revokedNotary[signer]) {
                revokedNotary[signer] = true;
                emit NotaryRevoked(signer);
            }
        }
        emit RecoveryStarted(currentEpoch);
        emit Paused(msg.sender);
    }

    /// @notice Maintenance/RPC outage pause that preserves keys. Cannot downgrade an
    /// emergency or resume around a pending rotation. Only governance schedules resume.
    function pauseOperational() external {
        if (msg.sender != guardian && msg.sender != governance) revert Unauthorized();
        if (recoveryRequired) revert RecoveryRequired();
        paused = true;
        if (proposedNotariesHash != bytes32(0)) {
            recoveryRequired = true;
            recoveryEpoch = currentEpoch;
        }
        _clearResume();
        emit Paused(msg.sender);
    }

    /// @notice Sequential recovery: scheduling BEFORE the required installation fails.
    /// Bind the authorization to the exact installed generation and configuration.
    function scheduleResume() external onlyGovernance {
        if (!paused) revert NotPaused();
        _requireRecoverable();
        resumeReadyAt = _timestampAfter(governanceDelay);
        resumeEpoch = currentEpoch;
        resumeConfigHash = currentConfigHash;
        emit ResumeScheduled(resumeReadyAt, currentEpoch, currentConfigHash);
    }

    function executeResume() external {
        if (!paused) revert NotPaused();
        if (resumeReadyAt == 0) revert NoProposal();
        _requireRecoverable();
        if (resumeEpoch != currentEpoch || resumeConfigHash != currentConfigHash) revert StaleResume();
        // Governance delay is at least two days; bounded timestamp skew cannot
        // materially bypass the recovery window.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < resumeReadyAt) revert TooEarly();
        paused = false;
        recoveryRequired = false;
        recoveryEpoch = 0;
        _clearResume();
        emit Resumed();
    }

    /// @notice Immutable governance may rotate the quorum, never move funds directly.
    /// Rotation invalidates ALL old certificates, including already queued ones.
    function proposeNotaries(address[] calldata signers, uint8 threshold_) external onlyGovernance {
        _validateNotaries(signers, threshold_);
        _clearResume();
        // A rotation proposed during a pause must finish even if subsequently cancelled.
        // Cancellation does not silently authorize returning to the old configuration.
        if (paused) {
            recoveryRequired = true;
            recoveryEpoch = currentEpoch;
        }
        proposedNotariesHash = keccak256(abi.encode(signers, threshold_));
        notariesReadyAt = _timestampAfter(governanceDelay);
        emit NotariesProposed(proposedNotariesHash, signers, threshold_, notariesReadyAt);
    }

    function cancelNotariesProposal() external {
        if (msg.sender != governance && msg.sender != guardian) revert Unauthorized();
        bytes32 proposal = proposedNotariesHash;
        if (proposal == bytes32(0)) revert NoProposal();
        delete proposedNotariesHash;
        delete notariesReadyAt;
        _clearResume();
        emit NotariesProposalCancelled(proposal);
    }

    function executeNotaries(address[] calldata signers, uint8 threshold_) external {
        if (proposedNotariesHash == bytes32(0)) revert NoProposal();
        if (proposedNotariesHash != keccak256(abi.encode(signers, threshold_))) revert InvalidConfiguration();
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < notariesReadyAt) revert TooEarly();
        // A proposal may predate an emergency that revoked its keys.
        _validateNotaries(signers, threshold_);
        delete proposedNotariesHash;
        delete notariesReadyAt;
        _clearResume();
        _installNotaries(signers, threshold_);
    }

    /// @dev USDT may accept funds into a frozen recipient and still return success.
    /// Balance deltas alone cannot detect that loss of spendability. Fail closed on
    /// policy lookup failure, pause, legacy-contract redirection or enabled fees.
    function _requireTokenUsable(address from, address to) private view {
        IUSDTPolicy policy = IUSDTPolicy(address(token));
        if (policy.paused() || policy.deprecated() || policy.basisPointsRate() != 0 || policy.maximumFee() != 0) {
            revert UnsafeTokenState();
        }
        if (policy.isBlackListed(from)) revert FrozenTokenAccount(from);
        if (to != from && policy.isBlackListed(to)) revert FrozenTokenAccount(to);
    }

    function _timestampAfter(uint256 delay) private view returns (uint64) {
        return _checkedUint64(block.timestamp + delay);
    }

    function _checkedUint64(uint256 value) private pure returns (uint64) {
        if (value > type(uint64).max) revert TimestampOverflow();
        // The explicit bound above proves that this narrowing conversion cannot truncate.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(value);
    }

    function _requireRecoverable() private view {
        if (proposedNotariesHash != bytes32(0)) revert RotationPending();
        if (recoveryRequired && currentEpoch <= recoveryEpoch) revert RecoveryRequired();
    }

    function _clearResume() private {
        resumeReadyAt = 0;
        resumeEpoch = 0;
        resumeConfigHash = bytes32(0);
    }

    function _validateNotaries(address[] memory signers, uint8 threshold_) private view {
        if (
            signers.length < 3 || signers.length > MAX_NOTARIES || threshold_ > signers.length
                || threshold_ <= signers.length * 2 / 3
        ) revert InvalidConfiguration();
        address previous = address(0);
        for (uint256 i; i < signers.length; ++i) {
            address signer = signers[i];
            if (revokedNotary[signer]) revert RevokedNotary();
            if (
                signer <= previous || signer == governance || signer == guardian || signer == address(token)
                    || signer == address(this)
            ) revert InvalidConfiguration();
            previous = signer;
        }
    }

    function _installNotaries(address[] memory signers, uint8 threshold_) private {
        ++currentEpoch;
        // The real outflow bucket is deliberately NOT reset by rotation.
        totalPendingAmount = 0;
        pendingCount = 0;
        firstPendingBurn = bytes32(0);
        lastPendingBurn = bytes32(0);
        threshold = threshold_;
        notaryCount = uint8(signers.length);
        currentConfigHash = keccak256(abi.encode(signers, threshold_));
        activeNotarySet = signers;
        for (uint256 i; i < signers.length; ++i) {
            notaryEpoch[signers[i]] = currentEpoch;
        }
        emit NotariesInstalled(currentEpoch, signers, threshold_);
    }
}
