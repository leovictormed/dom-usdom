// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IUSDTPolicy} from "./IUSDTPolicy.sol";

/// @notice The verifier must authenticate DOM consensus finality, the USDOM state
/// transition and inclusion of the exact public burn statement. Implementations
/// may hide all unrelated notes and transfer history inside a zero-knowledge proof.
interface IDOMFinalizedBurnVerifier {
    function verifierConfigHash() external view returns (bytes32);
    function verifyFinalizedBurn(bytes32 statementHash, bytes calldata proof) external view returns (bytes32);
}

/// @title USDOM proof-authorized USDT reserve candidate
/// @notice This candidate deliberately cannot deploy on Ethereum mainnet until
/// ratified verifier bytecode and configuration hashes are compiled into the
/// release. It contains no notary fallback, upgrade, sweep, arbitrary call or mint.
contract USDOMProofReserve is ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public constant ETHEREUM_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    bytes32 public constant ETHEREUM_USDT_CODE_HASH =
        0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55;
    uint256 public constant REFILL_PERIOD = 1 days;
    /// @notice Maximum age of one queue reservation. A finalized native burn is
    /// an irreversible debt of the reserve, so expiry releases only the queue
    /// reservation and never destroys the underlying right to prove it again.
    uint256 public constant MAX_CERTIFICATE_LIFETIME = 7 days;
    uint256 public constant MIN_EXECUTION_WINDOW = 1 hours;
    uint256 public constant ETHEREUM_MAINNET_GENESIS_TIME = 1_606_824_023;
    uint256 public constant ETHEREUM_SECONDS_PER_SLOT = 12;
    uint256 public constant MAX_FINALITY_AGE_SLOTS = MAX_CERTIFICATE_LIFETIME / ETHEREUM_SECONDS_PER_SLOT;
    uint256 public constant MAX_PRUNE_BATCH = 256;
    uint256 public constant MAX_PROOF_BYTES = 64 * 1024;
    uint256 public constant VERIFIER_GAS_LIMIT = 5_000_000;
    uint256 public constant BN254_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 public constant RESERVE_IDENTITY_TYPEHASH = keccak256(
        "ReserveIdentity(uint256 ethereumChainId,address reserve,address token,bytes32 tokenCodeHash,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash,bytes32 domDomain,bytes32 activationScheduleCommitment)"
    );
    bytes32 public constant RESERVE_POLICY_TYPEHASH = keccak256(
        "ReservePolicy(address governance,bytes32 governanceCodeHash,address guardian,bytes32 guardianCodeHash,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity)"
    );
    bytes32 public constant RESERVE_CONFIG_TYPEHASH =
        keccak256("ReserveConfig(bytes32 identityHash,bytes32 policyHash)");

    // A production release must replace all zeros with values from an externally
    // validated, immutable release and its ratified deployment manifest. Zeros
    // keep chain ID 1 fail closed.
    bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_RESERVE_CONFIG_HASH = bytes32(0);

    bytes32 public constant BURN_STATEMENT_TYPEHASH = keccak256(
        "FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)"
    );
    /// @notice Canonical pre-finality intent committed by the native DOM burn.
    /// The finalized statement extends this exact intent with DOM block/state
    /// identity; the proof must demonstrate both relations without substitution.
    bytes32 public constant BURN_INTENT_TYPEHASH = keccak256(
        "BurnIntent(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 validUntil,uint256 ethereumChainId,address reserve)"
    );

    IERC20 public immutable token;
    bytes32 public immutable tokenCodeHash;
    IDOMFinalizedBurnVerifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable verifierConfigHash;
    bytes32 public immutable reserveConfigHash;
    bytes32 public immutable domDomain;
    bytes32 public immutable activationScheduleCommitment;
    address public immutable governance;
    bytes32 public immutable governanceCodeHash;
    address public immutable guardian;
    bytes32 public immutable guardianCodeHash;
    uint64 public immutable withdrawalDelay;
    uint64 public immutable governanceDelay;
    uint64 public immutable maxOutstanding;
    uint64 public immutable outflowCapacity;

    struct Config {
        IERC20 token;
        IDOMFinalizedBurnVerifier verifier;
        bytes32 domDomain;
        bytes32 activationScheduleCommitment;
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

    struct FinalizedBurn {
        bytes32 burnId;
        bytes32 requestId;
        address recipient;
        uint64 amount;
        bytes32 domDomain;
        uint64 height;
        bytes32 blockHash;
        bytes32 stateRoot;
        uint64 finalityBeaconSlot;
        /// @notice Native burn-admission deadline authenticated by the proof.
        /// It does not extinguish the reserve's debt after an irreversible burn.
        uint64 validUntil;
    }

    struct PendingWithdrawal {
        bytes32 statementHash;
        bytes32 requestId;
        uint64 readyAt;
        uint64 expiresAt;
        uint64 queueEpoch;
        uint64 amount;
        bytes32 previous;
        bytes32 next;
    }

    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => bool) public paidBurns;
    mapping(bytes32 => bool) public paidRequests;
    mapping(bytes32 => PendingWithdrawal) public pendingWithdrawals;
    mapping(bytes32 => bytes32) public pendingRequests;

    uint256 public totalDeposited;
    uint256 public totalReleased;
    uint256 public totalPendingAmount;
    uint256 public pendingCount;
    bytes32 public firstPendingBurn;
    bytes32 public lastPendingBurn;
    /// @notice Emergency pauses invalidate the complete prior queue in O(1).
    uint64 public queueEpoch;
    bool public paused;
    uint64 public resumeReadyAt;
    uint64 private bucketBalance;
    uint64 private bucketUpdatedAt;

    event Deposited(bytes32 indexed id, address indexed funder, uint64 amount, bytes32 receivingCommitment);
    event WithdrawalQueued(
        bytes32 indexed burnId, bytes32 indexed requestId, bytes32 statementHash, uint64 readyAt, uint64 expiresAt
    );
    event FinalizedBurnProved(bytes32 indexed burnId, FinalizedBurn burn);
    event Released(
        bytes32 indexed burnId,
        bytes32 indexed requestId,
        address indexed recipient,
        uint64 amount,
        uint64 height,
        bytes32 blockHash,
        bytes32 stateRoot,
        uint64 finalityBeaconSlot
    );
    event WithdrawalDiscarded(bytes32 indexed burnId, bytes32 indexed requestId);
    event WithdrawalQueueInvalidated(uint64 indexed newQueueEpoch, uint256 invalidatedCount, uint256 invalidatedAmount);
    event Paused(address indexed caller);
    event ResumeScheduled(uint64 readyAt);
    event Resumed();

    error InvalidConfiguration();
    error ProductionUnavailable();
    error Unauthorized();
    error StaleEmergency();
    error IsPaused();
    error NotPaused();
    error InvalidDeposit();
    error InvalidBurn();
    error InvalidProof();
    error TokenChanged();
    error VerifierChanged();
    error ControlPlaneChanged();
    error AlreadyUsed();
    error InvalidCertificateWindow();
    error PendingMismatch();
    error TooEarly();
    error StaleCertificate();
    error StillValid();
    error UnsupportedToken();
    error Insolvent();
    error ExposureLimit();
    error OutflowLimit();
    error NoProposal();
    error TimestampOverflow();
    error UnsafeTokenState();
    error FrozenTokenAccount(address account);

    modifier onlyGovernance() {
        if (msg.sender != governance) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _requireControlPlaneUnchanged();
        _;
    }

    constructor(Config memory config) {
        bytes32 tokenHash = address(config.token).codehash;
        bytes32 codeHash = address(config.verifier).codehash;
        if (
            address(config.token).code.length == 0 || address(config.verifier).code.length == 0
                || address(config.token) == address(config.verifier) || tokenHash == bytes32(0)
                || codeHash == bytes32(0) || config.domDomain == bytes32(0)
                || config.activationScheduleCommitment == bytes32(0) || config.governance.code.length == 0
                || config.guardian.code.length == 0 || config.guardian == config.governance
                || config.governance == address(config.token) || config.guardian == address(config.token)
                || config.governance == address(config.verifier) || config.guardian == address(config.verifier)
                || config.withdrawalDelay < 6 hours || config.withdrawalDelay > 3 days
                || config.governanceDelay < 2 days || config.governanceDelay > 30 days || config.maxOutstanding == 0
                || config.outflowCapacity == 0 || config.outflowCapacity > config.maxOutstanding
        ) revert InvalidConfiguration();
        if (IERC20Metadata(address(config.token)).decimals() != 6) revert UnsupportedToken();

        bytes32 configHash = _readVerifierConfig(config.verifier);
        if (configHash == bytes32(0)) revert InvalidConfiguration();
        bytes32 deploymentConfigHash = _reserveConfigHash(config, tokenHash, codeHash, configHash);
        if (
            block.chainid == 1
                && (address(config.token) != ETHEREUM_USDT
                    || tokenHash != ETHEREUM_USDT_CODE_HASH
                    || PRODUCTION_VERIFIER_CODE_HASH == bytes32(0)
                    || PRODUCTION_VERIFIER_CONFIG_HASH == bytes32(0)
                    || PRODUCTION_RESERVE_CONFIG_HASH == bytes32(0)
                    || codeHash != PRODUCTION_VERIFIER_CODE_HASH
                    || configHash != PRODUCTION_VERIFIER_CONFIG_HASH
                    || deploymentConfigHash != PRODUCTION_RESERVE_CONFIG_HASH)
        ) revert ProductionUnavailable();

        token = config.token;
        tokenCodeHash = tokenHash;
        verifier = config.verifier;
        verifierCodeHash = codeHash;
        verifierConfigHash = configHash;
        reserveConfigHash = deploymentConfigHash;
        domDomain = config.domDomain;
        activationScheduleCommitment = config.activationScheduleCommitment;
        governance = config.governance;
        governanceCodeHash = config.governance.codehash;
        guardian = config.guardian;
        guardianCodeHash = config.guardian.codehash;
        withdrawalDelay = config.withdrawalDelay;
        governanceDelay = config.governanceDelay;
        maxOutstanding = config.maxOutstanding;
        outflowCapacity = config.outflowCapacity;
        bucketBalance = config.outflowCapacity;
        bucketUpdatedAt = _checkedUint64(block.timestamp);
        queueEpoch = 1;
        _requireTokenUsable(address(this), address(this));
        if (initialPauseRequired(block.chainid)) {
            paused = true;
            // Construction has no externally callable runtime and the event is
            // reverted if any constructor check fails.
            // forge-lint: disable-next-line(reentrancy-events)
            emit Paused(msg.sender);
        }
    }

    /// @notice A mainnet release must remain closed through its complete
    /// post-deployment verification and the ordinary governance resume delay.
    function initialPauseRequired(uint256 chainId) public pure returns (bool) {
        return chainId == 1;
    }

    function outstanding() public view returns (uint256) {
        return totalDeposited - totalReleased;
    }

    function unreservedCollateral() public view returns (uint256) {
        return outstanding() - totalPendingAmount;
    }

    function depositId(address funder, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), funder, salt));
    }

    function burnStatementHash(FinalizedBurn calldata burn) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                BURN_STATEMENT_TYPEHASH,
                burn.burnId,
                burn.requestId,
                burn.recipient,
                burn.amount,
                burn.domDomain,
                burn.height,
                burn.blockHash,
                burn.stateRoot,
                burn.finalityBeaconSlot,
                burn.validUntil,
                block.chainid,
                address(this),
                activationScheduleCommitment
            )
        );
    }

    /// @notice Hash of the exact withdrawal intent that native USDOM consensus
    /// must commit before block height/finality fields exist.
    function burnIntentHash(FinalizedBurn calldata burn) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                BURN_INTENT_TYPEHASH,
                burn.burnId,
                burn.requestId,
                burn.recipient,
                burn.amount,
                burn.domDomain,
                burn.validUntil,
                block.chainid,
                address(this)
            )
        );
    }

    function deposit(uint64 amount, bytes32 salt, bytes32 receivingCommitment)
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 id)
    {
        if (amount == 0 || receivingCommitment == bytes32(0) || uint256(receivingCommitment) >= BN254_SCALAR_FIELD) revert InvalidDeposit();
        _requireVerifierUnchanged();
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
        // Exact deltas deliberately reject fee-on-transfer, rebasing and other
        // collateral semantics that would break one-to-one accounting.
        // forge-lint: disable-next-item(incorrect-strict-equality)
        if (
            token.balanceOf(address(this)) != reserveBefore + amount
                || token.balanceOf(msg.sender) + amount != funderBefore
        ) revert UnsupportedToken();
        // The non-reentrant transfer and exact postcondition precede this log;
        // any callback or failed postcondition reverts the complete transaction.
        // forge-lint: disable-next-line(reentrancy-events)
        emit Deposited(id, msg.sender, amount, receivingCommitment);
    }

    /// @notice The proof is verified once, before collateral is reserved. Execution
    /// later uses the exact stored statement hash and cannot substitute any field.
    function queueWithdrawal(FinalizedBurn calldata burn, bytes calldata proof) external nonReentrant whenNotPaused {
        if (
            burn.burnId == bytes32(0) || burn.requestId == bytes32(0) || burn.recipient == address(0)
                || burn.recipient == address(this) || burn.recipient == address(token) || burn.amount == 0
                || burn.domDomain != domDomain || burn.height == 0 || burn.blockHash == bytes32(0)
                || burn.stateRoot == bytes32(0) || burn.finalityBeaconSlot == 0 || burn.validUntil == 0
                || proof.length == 0 || proof.length > MAX_PROOF_BYTES
        ) revert InvalidBurn();
        _requireRecentFinalitySlot(burn.finalityBeaconSlot);
        _requireTokenUsable(address(this), burn.recipient);
        if (burn.amount > outflowCapacity) revert OutflowLimit();
        uint64 readyAt = _timestampAfter(withdrawalDelay);
        uint64 expiresAt = _timestampAfter(MAX_CERTIFICATE_LIFETIME);
        // Native consensus already proves that validUntil was derived from a
        // recent authenticated Ethereum anchor when the irreversible burn was
        // admitted. Reject an intent that still claims an excessive future
        // deadline, but do not erase the payout debt merely because that
        // original admission deadline is now in the past. The independently
        // computed queue lease above can be discarded and renewed safely.
        // forge-lint: disable-next-line(block-timestamp)
        if (burn.validUntil > expiresAt) {
            revert InvalidCertificateWindow();
        }
        if (burn.amount > unreservedCollateral() || token.balanceOf(address(this)) < outstanding()) revert Insolvent();
        PendingWithdrawal storage existing = pendingWithdrawals[burn.burnId];
        if (
            paidBurns[burn.burnId] || paidRequests[burn.requestId]
                || (existing.statementHash != bytes32(0) && existing.queueEpoch == queueEpoch)
                || _hasActivePendingRequest(burn.requestId)
        ) revert AlreadyUsed();

        bytes32 statementHash = burnStatementHash(burn);
        _verify(statementHash, proof);
        pendingWithdrawals[burn.burnId] = PendingWithdrawal(
            statementHash, burn.requestId, readyAt, expiresAt, queueEpoch, burn.amount, lastPendingBurn, bytes32(0)
        );
        if (lastPendingBurn == bytes32(0)) firstPendingBurn = burn.burnId;
        else pendingWithdrawals[lastPendingBurn].next = burn.burnId;
        lastPendingBurn = burn.burnId;
        ++pendingCount;
        totalPendingAmount += burn.amount;
        pendingRequests[burn.requestId] = burn.burnId;
        // The verifier call precedes state mutation and nonReentrant prevents
        // verifier callbacks from entering another queue operation.
        // forge-lint: disable-next-line(reentrancy-events)
        emit WithdrawalQueued(burn.burnId, burn.requestId, statementHash, readyAt, expiresAt);
        // forge-lint: disable-next-line(reentrancy-events)
        emit FinalizedBurnProved(burn.burnId, burn);
    }

    function executeWithdrawal(FinalizedBurn calldata burn) external nonReentrant whenNotPaused {
        PendingWithdrawal memory pending = pendingWithdrawals[burn.burnId];
        if (pending.statementHash == bytes32(0) || pending.statementHash != burnStatementHash(burn)) {
            revert PendingMismatch();
        }
        if (pending.queueEpoch != queueEpoch) revert StaleCertificate();
        // Ethereum timestamps are the protocol clock. The configured delay is
        // at least six hours, far above the bounded proposer timestamp skew.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > pending.expiresAt) revert StaleCertificate();
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < pending.readyAt) revert TooEarly();
        _requireVerifierUnchanged();
        _requireTokenUsable(address(this), burn.recipient);
        uint256 credited = outstanding();
        if (burn.amount > credited) revert Insolvent();
        uint256 available = availableOutflow();
        if (burn.amount > available) revert OutflowLimit();
        uint256 reserveBefore = token.balanceOf(address(this));
        if (reserveBefore < credited) revert Insolvent();
        uint256 recipientBefore = token.balanceOf(burn.recipient);

        bucketBalance = _checkedUint64(available - burn.amount);
        bucketUpdatedAt = _checkedUint64(block.timestamp);
        totalReleased += burn.amount;
        paidBurns[burn.burnId] = true;
        paidRequests[burn.requestId] = true;
        _removePending(burn.burnId, pending);

        token.safeTransfer(burn.recipient, burn.amount);
        // Exact deltas are a required USDT collateral invariant, not a generic
        // ERC-20 compatibility assumption.
        // forge-lint: disable-next-item(incorrect-strict-equality)
        if (
            token.balanceOf(address(this)) + burn.amount != reserveBefore
                || token.balanceOf(burn.recipient) != recipientBefore + burn.amount
        ) revert UnsupportedToken();
        // State is effects-first and nonReentrant; a failed transfer or balance
        // postcondition reverts this event with the whole transaction.
        // forge-lint: disable-next-item(reentrancy-events)
        emit Released(
            burn.burnId,
            burn.requestId,
            burn.recipient,
            burn.amount,
            burn.height,
            burn.blockHash,
            burn.stateRoot,
            burn.finalityBeaconSlot
        );
    }

    function discardWithdrawal(bytes32 burnId) external nonReentrant {
        PendingWithdrawal memory pending = pendingWithdrawals[burnId];
        if (pending.statementHash == bytes32(0)) revert PendingMismatch();
        // forge-lint: disable-next-line(block-timestamp)
        if (pending.queueEpoch == queueEpoch && block.timestamp <= pending.expiresAt) revert StillValid();
        _removePending(burnId, pending);
        emit WithdrawalDiscarded(burnId, pending.requestId);
    }

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

    /// @notice Bounded cleanup for expired entries behind a still-valid queue
    /// head and for old entries invalidated by an emergency pause. Unknown,
    /// duplicate and currently valid identifiers are skipped so one candidate
    /// cannot prevent independent garbage collection in the same transaction.
    function pruneDiscardable(bytes32[] calldata burnIds) external nonReentrant returns (uint256 removed) {
        if (burnIds.length == 0 || burnIds.length > MAX_PRUNE_BATCH) revert InvalidConfiguration();
        for (uint256 i; i < burnIds.length; ++i) {
            bytes32 burnId = burnIds[i];
            PendingWithdrawal memory pending = pendingWithdrawals[burnId];
            // Expiry is defined by the Ethereum protocol clock; this cleanup
            // grants no payout authority and may only release stale storage.
            if (
                pending.statementHash == bytes32(0)
                    // forge-lint: disable-next-line(block-timestamp)
                    || (pending.queueEpoch == queueEpoch && block.timestamp <= pending.expiresAt)
            ) {
                continue;
            }
            _removePending(burnId, pending);
            emit WithdrawalDiscarded(burnId, pending.requestId);
            ++removed;
        }
    }

    function availableOutflow() public view returns (uint256) {
        uint256 elapsed = block.timestamp - bucketUpdatedAt;
        // Ethereum timestamp is the rate-limiter's consensus clock. A one-day
        // refill makes bounded proposer skew economically negligible.
        // forge-lint: disable-next-line(block-timestamp)
        if (elapsed >= REFILL_PERIOD) return outflowCapacity;
        uint256 available = bucketBalance + elapsed * outflowCapacity / REFILL_PERIOD;
        // forge-lint: disable-next-line(block-timestamp)
        return available > outflowCapacity ? outflowCapacity : available;
    }

    function pause() external {
        _pause();
    }

    /// @notice Automation stop bound to the queue generation it inspected. A
    /// delayed transaction cannot invalidate a reviewed replacement queue.
    function pauseQueueEpoch(uint64 expectedQueueEpoch) external {
        if (msg.sender != guardian && msg.sender != governance) revert Unauthorized();
        if (expectedQueueEpoch != queueEpoch) revert StaleEmergency();
        _pauseState();
    }

    function _pause() private {
        if (msg.sender != guardian && msg.sender != governance) revert Unauthorized();
        _pauseState();
    }

    function _pauseState() private {
        if (!paused) {
            paused = true;
            uint256 invalidatedCount = pendingCount;
            uint256 invalidatedAmount = totalPendingAmount;
            ++queueEpoch;
            // WithdrawalQueueInvalidated below is the aggregate event for this
            // O(1) queue-generation reset.
            // forge-lint: disable-next-line(missing-events-access-control)
            pendingCount = 0;
            // forge-lint: disable-next-line(missing-events-access-control)
            totalPendingAmount = 0;
            // forge-lint: disable-next-line(missing-events-access-control)
            firstPendingBurn = bytes32(0);
            // forge-lint: disable-next-line(missing-events-access-control)
            lastPendingBurn = bytes32(0);
            emit WithdrawalQueueInvalidated(queueEpoch, invalidatedCount, invalidatedAmount);
        }
        // Paused below records cancellation of any scheduled resume.
        // forge-lint: disable-next-line(missing-events-access-control)
        resumeReadyAt = 0;
        emit Paused(msg.sender);
    }

    function scheduleResume() external onlyGovernance {
        if (!paused) revert NotPaused();
        _requireControlPlaneUnchanged();
        // ResumeScheduled below records the exact authorization timestamp.
        // forge-lint: disable-next-line(missing-events-access-control)
        resumeReadyAt = _timestampAfter(governanceDelay);
        emit ResumeScheduled(resumeReadyAt);
    }

    function executeResume() external {
        if (!paused) revert NotPaused();
        if (resumeReadyAt == 0) revert NoProposal();
        // Governance delay is at least two days; bounded timestamp skew cannot
        // materially bypass the recovery window.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < resumeReadyAt) revert TooEarly();
        _requireControlPlaneUnchanged();
        _requireVerifierUnchanged();
        _requireTokenUsable(address(this), address(this));
        paused = false;
        resumeReadyAt = 0;
        // All external checks above are read-only and fail closed; their code
        // hashes are immutable and neither address is a control-plane signer.
        // forge-lint: disable-next-line(reentrancy-events)
        emit Resumed();
    }

    function _verify(bytes32 statementHash, bytes calldata proof) private view {
        _requireVerifierUnchanged();
        (bool ok, bytes32 result) = _staticcallWord(
            address(verifier),
            VERIFIER_GAS_LIMIT,
            abi.encodeCall(IDOMFinalizedBurnVerifier.verifyFinalizedBurn, (statementHash, proof))
        );
        if (!ok || result != PROOF_ACCEPTED) revert InvalidProof();
    }

    function _requireRecentFinalitySlot(uint64 finalityBeaconSlot) private view {
        // Timestamp is the EVM consensus clock intentionally used to reject future Beacon slots.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < ETHEREUM_MAINNET_GENESIS_TIME) revert InvalidBurn();
        uint256 currentSlot = (block.timestamp - ETHEREUM_MAINNET_GENESIS_TIME) / ETHEREUM_SECONDS_PER_SLOT;
        // forge-lint: disable-next-line(block-timestamp)
        if (finalityBeaconSlot > currentSlot || currentSlot - finalityBeaconSlot > MAX_FINALITY_AGE_SLOTS) {
            revert InvalidBurn();
        }
    }

    function _readVerifierConfig(IDOMFinalizedBurnVerifier candidate) private view returns (bytes32 configHash) {
        (bool ok, bytes32 result) = _staticcallWord(
            address(candidate), 50_000, abi.encodeCall(IDOMFinalizedBurnVerifier.verifierConfigHash, ())
        );
        if (!ok) revert InvalidConfiguration();
        configHash = result;
    }

    function _requireVerifierUnchanged() private view {
        if (address(verifier).codehash != verifierCodeHash || _readVerifierConfig(verifier) != verifierConfigHash) {
            revert VerifierChanged();
        }
    }

    function _requireControlPlaneUnchanged() private view {
        if (governance.codehash != governanceCodeHash || guardian.codehash != guardianCodeHash) {
            revert ControlPlaneChanged();
        }
    }

    function _reserveConfigHash(Config memory config, bytes32 tokenHash, bytes32 codeHash, bytes32 configHash)
        private
        view
        returns (bytes32)
    {
        bytes32 identityHash = keccak256(
            abi.encode(
                RESERVE_IDENTITY_TYPEHASH,
                block.chainid,
                address(this),
                address(config.token),
                tokenHash,
                address(config.verifier),
                codeHash,
                configHash,
                config.domDomain,
                config.activationScheduleCommitment
            )
        );
        bytes32 policyHash = keccak256(
            abi.encode(
                RESERVE_POLICY_TYPEHASH,
                config.governance,
                config.governance.codehash,
                config.guardian,
                config.guardian.codehash,
                config.withdrawalDelay,
                config.governanceDelay,
                config.maxOutstanding,
                config.outflowCapacity
            )
        );
        return keccak256(abi.encode(RESERVE_CONFIG_TYPEHASH, identityHash, policyHash));
    }

    /// @dev Copies exactly one return word. Oversized return data is rejected
    /// without allocating or copying attacker-selected bytes into Solidity memory.
    function _staticcallWord(address target, uint256 gasLimit, bytes memory callData)
        private
        view
        returns (bool success, bytes32 word)
    {
        uint256 returnSize;
        assembly ("memory-safe") {
            let output := mload(0x40)
            success := staticcall(gasLimit, target, add(callData, 32), mload(callData), output, 32)
            returnSize := returndatasize()
            word := mload(output)
        }
        success = success && returnSize == 32;
    }

    function _removePending(bytes32 burnId, PendingWithdrawal memory pending) private {
        if (pending.queueEpoch == queueEpoch) {
            if (pending.previous == bytes32(0)) firstPendingBurn = pending.next;
            else pendingWithdrawals[pending.previous].next = pending.next;
            if (pending.next == bytes32(0)) lastPendingBurn = pending.previous;
            else pendingWithdrawals[pending.next].previous = pending.previous;
            totalPendingAmount -= pending.amount;
            --pendingCount;
        }
        if (pendingRequests[pending.requestId] == burnId) delete pendingRequests[pending.requestId];
        delete pendingWithdrawals[burnId];
    }

    function _hasActivePendingRequest(bytes32 requestId) private view returns (bool) {
        bytes32 burnId = pendingRequests[requestId];
        if (burnId == bytes32(0)) return false;
        PendingWithdrawal storage pending = pendingWithdrawals[burnId];
        return pending.statementHash != bytes32(0) && pending.queueEpoch == queueEpoch && pending.requestId == requestId;
    }

    function _requireTokenUsable(address from, address to) private view {
        if (address(token).codehash != tokenCodeHash) revert TokenChanged();
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
}
