// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IUSDTPolicy} from "./IUSDTPolicy.sol";

/// @notice The verifier must authenticate DOM consensus finality, the USDOM state
/// transition and inclusion of the exact public burn statement. Implementations
/// may hide all unrelated notes and transfer history inside a zero-knowledge proof.
interface IDOMFinalizedBurnVerifier {
    function verifierConfigHash() external view returns (bytes32);
    function verifyFinalizedBurn(bytes32 statementHash, bytes calldata proof) external view returns (bytes32);
}

/// @notice Minimal immutable registry boundary used only for graceful shutdown.
interface IDOMGracefulShutdownRegistry {
    function bridgeDomain() external view returns (bytes32);
    function activationScheduleCommitment() external view returns (bytes32);
    function checkpointConfigHash() external view returns (bytes32);
    function halted() external view returns (bool);
    function gracefullyShutdown() external view returns (bool);
    function latestIssuanceClosed() external view returns (bool);
    function latestTotalIssued() external view returns (uint128);
    function latestTotalBurned() external view returns (uint128);
}

/// @title USDOM proof-authorized USDT reserve candidate
/// @notice This candidate deliberately cannot deploy on Ethereum mainnet until
/// ratified verifier bytecode and configuration hashes are compiled into the
/// release. It contains no notary fallback, upgrade, sweep, arbitrary call or mint.
contract USDOMProofReserve is ReentrancyGuard {
    address public constant ETHEREUM_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    bytes32 public constant ETHEREUM_USDT_CODE_HASH =
        0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55;
    uint256 public constant REFILL_PERIOD = 1 days;
    /// @notice Maximum age of one queue reservation. A finalized native burn is
    /// an irreversible debt of the reserve, so expiry releases only its queue
    /// lease. The collateral debt remains reserved until successful payment.
    uint256 public constant MAX_CERTIFICATE_LIFETIME = 7 days;
    uint256 public constant MIN_EXECUTION_WINDOW = 1 hours;
    uint256 public constant ETHEREUM_MAINNET_GENESIS_TIME = 1_606_824_023;
    uint256 public constant ETHEREUM_SECONDS_PER_SLOT = 12;
    uint256 public constant MAX_FINALITY_AGE_SLOTS = MAX_CERTIFICATE_LIFETIME / ETHEREUM_SECONDS_PER_SLOT;
    uint256 public constant MAX_PRUNE_BATCH = 256;
    /// @notice Canonical RISC Zero Groth16 EVM seal: selector plus eight BN254 words.
    bytes4 private constant RISC_ZERO_GROTH16_V3_SELECTOR = 0x73c457ba;
    uint256 public constant EVM_PROOF_BYTES = 4 + 8 * 32;
    uint256 public constant MAX_PROOF_BYTES = EVM_PROOF_BYTES;
    uint256 public constant VERIFIER_GAS_LIMIT = 5_000_000;
    uint256 public constant TOKEN_GAS_LIMIT = 500_000;
    uint256 public constant REGISTRY_GAS_LIMIT = 100_000;
    uint256 public constant CONTROL_PLANE_GAS_LIMIT = 50_000;
    uint256 public constant CONTROL_PLANE_THRESHOLD = 2;
    uint256 public constant CONTROL_PLANE_OWNER_COUNT = 3;
    uint256 public constant SAFE_GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    uint256 public constant SAFE_FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    address public constant SAFE_MAINNET_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    bytes32 public constant SAFE_MAINNET_SINGLETON_CODE_HASH =
        0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4;
    bytes32 public constant SAFE_MAINNET_PROXY_CODE_HASH =
        0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c;
    address public constant SAFE_MAINNET_FALLBACK_HANDLER = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    bytes32 public constant SAFE_MAINNET_FALLBACK_HANDLER_CODE_HASH =
        0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9;
    bytes4 private constant SAFE_GET_STORAGE_AT_SELECTOR = 0x5624b25b;
    uint256 public constant BN254_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 public constant RESERVE_IDENTITY_TYPEHASH = keccak256(
        "ReserveIdentity(uint256 ethereumChainId,address reserve,address token,bytes32 tokenCodeHash,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash,address checkpointRegistry,bytes32 checkpointRegistryCodeHash,bytes32 checkpointConfigHash,bytes32 domDomain,bytes32 activationScheduleCommitment)"
    );
    bytes32 public constant RESERVE_PREACTIVATION_IDENTITY_TYPEHASH = keccak256(
        "ReservePreActivationIdentity(uint256 ethereumChainId,address reserve,address token,bytes32 tokenCodeHash,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash,address checkpointRegistry,bytes32 checkpointRegistryCodeHash,bytes32 checkpointConfigHash,bytes32 domDomain)"
    );
    bytes32 public constant CONTROL_PLANE_IDENTITY_TYPEHASH = keccak256(
        "ControlPlaneIdentity(address account,bytes32 accountCodeHash,address implementation,bytes32 implementationCodeHash,bytes32 ownersCommitment)"
    );
    bytes32 public constant RESERVE_POLICY_TYPEHASH = keccak256(
        "ReservePolicy(bytes32 governanceIdentityHash,bytes32 guardianIdentityHash,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity)"
    );
    bytes32 public constant RESERVE_CONFIG_TYPEHASH =
        keccak256("ReserveConfig(bytes32 identityHash,bytes32 policyHash)");
    bytes32 public constant RESERVE_PREACTIVATION_CONFIG_TYPEHASH =
        keccak256("ReservePreActivationConfig(bytes32 identityHash,bytes32 policyHash)");

    // A production release must replace both zeros with independently derived
    // verifier values. Release-specific reserve identity is constructor state:
    // embedding it in runtime bytecode would create a cryptographic cycle with
    // the native activation state that commits this runtime's code hash.
    bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH = bytes32(0);

    bytes32 public constant BURN_STATEMENT_TYPEHASH = keccak256(
        "FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)"
    );
    /// @notice Canonical pre-finality intent committed by the native DOM burn.
    /// The finalized statement extends this exact intent with DOM block/state
    /// identity; the proof must demonstrate both relations without substitution.
    bytes32 public constant BURN_INTENT_TYPEHASH = keccak256(
        "BurnIntent(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 validUntil,uint256 ethereumChainId,address reserve)"
    );
    /// @notice Permanent proved-debt identity. A renewed proof may advance only
    /// the Ethereum finality slot; DOM inclusion, payout and release identity
    /// remain byte-for-byte bound to the first accepted proof.
    bytes32 public constant BURN_DEBT_TYPEHASH = keccak256(
        "FinalizedBurnDebt(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)"
    );

    IERC20 public immutable token;
    bytes32 public immutable tokenCodeHash;
    IDOMFinalizedBurnVerifier public immutable verifier;
    IDOMGracefulShutdownRegistry public immutable checkpointRegistry;
    bytes32 public immutable checkpointRegistryCodeHash;
    bytes32 public immutable checkpointRegistryConfigHash;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable verifierConfigHash;
    bytes32 public immutable domDomain;
    address public immutable governance;
    bytes32 public immutable governanceCodeHash;
    address public immutable governanceImplementation;
    bytes32 public immutable governanceImplementationCodeHash;
    bytes32 public immutable governanceOwnersCommitment;
    address public immutable guardian;
    bytes32 public immutable guardianCodeHash;
    address public immutable guardianImplementation;
    bytes32 public immutable guardianImplementationCodeHash;
    bytes32 public immutable guardianOwnersCommitment;
    uint64 public immutable withdrawalDelay;
    uint64 public immutable governanceDelay;
    uint64 public immutable maxOutstanding;
    uint64 public immutable outflowCapacity;

    /// @notice Exact constructor identity retained in state so the deployed
    /// runtime code hash can be committed before native activation is derived.
    bytes32 public reserveConfigHash;
    bytes32 public activationScheduleCommitment;

    struct Config {
        IERC20 token;
        IDOMFinalizedBurnVerifier verifier;
        IDOMGracefulShutdownRegistry checkpointRegistry;
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
    /// @notice Audit hash of the first accepted statement. The permanent debt
    /// binding below permits later statements to advance only finality.
    mapping(bytes32 => bytes32) public provedBurnStatements;
    mapping(bytes32 => bytes32) public provedBurnDebts;
    /// @notice Highest authenticated Ethereum finality slot for this debt.
    /// Emergency queue resets may reuse it while recent, but never regress it.
    mapping(bytes32 => uint64) public provedBurnFinalitySlots;
    mapping(bytes32 => bytes32) public provedRequestBurns;

    uint256 public totalDeposited;
    uint256 public totalReleased;
    /// @notice Collateral owed to every accepted, unpaid finalized burn. Queue
    /// expiry or emergency invalidation never releases this permanent debt.
    uint256 public totalProvedDebtAmount;
    /// @notice Amount represented by executable leases in the current queue;
    /// this is a subset of, and never a replacement for, permanent proved debt.
    uint256 public totalPendingAmount;
    uint256 public pendingCount;
    bytes32 public firstPendingBurn;
    bytes32 public lastPendingBurn;
    /// @notice Emergency pauses invalidate the complete prior queue in O(1).
    uint64 public queueEpoch;
    bool public paused;
    /// @notice Irreversible ingress shutdown. Existing proved burn debts and
    /// withdrawal execution remain live without accepting new collateral.
    bool public depositsClosed;
    /// @notice Terminal proof-authorized completion after every reserve debt is paid.
    bool public gracefullyShutdown;
    uint64 public resumeReadyAt;
    uint64 private bucketBalance;
    uint64 private bucketUpdatedAt;

    event Deposited(bytes32 indexed id, address indexed funder, uint64 amount, bytes32 receivingCommitment);
    event WithdrawalQueued(
        bytes32 indexed burnId, bytes32 indexed requestId, bytes32 statementHash, uint64 readyAt, uint64 expiresAt
    );
    event FinalizedBurnProved(bytes32 indexed burnId, FinalizedBurn burn);
    event WithdrawalLeaseV2(
        bytes32 indexed burnId,
        bytes32 indexed requestId,
        uint64 amount,
        uint64 indexed queueEpoch,
        bytes32 statementHash,
        uint64 readyAt,
        uint64 expiresAt,
        uint64 finalityBeaconSlot,
        bool renewal
    );
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
    event WithdrawalDiscardedV2(
        bytes32 indexed burnId, bytes32 indexed requestId, uint64 amount, uint64 indexed leaseEpoch
    );
    event ProvedDebtSettled(
        bytes32 indexed burnId,
        bytes32 indexed requestId,
        uint64 amount,
        uint64 indexed leaseEpoch,
        uint256 remainingProvedDebt
    );
    event WithdrawalQueueInvalidated(uint64 indexed newQueueEpoch, uint256 invalidatedCount, uint256 invalidatedAmount);
    event Paused(address indexed caller);
    event DepositsPermanentlyClosed(address indexed caller);
    event GracefullyShutdown(address indexed checkpointRegistry, bytes32 indexed checkpointConfigHash, uint256 settled);
    /// @notice Canonical closure evidence consumed by DOM consensus. The
    /// emitter supplies chain/reserve identity; these fields bind the exact
    /// collateral total and immutable release configuration.
    event DepositsClosedV2(
        uint256 totalDeposited, bytes32 reserveConfigHash, bytes32 activationScheduleCommitment, bytes32 domDomain
    );
    event ResumeScheduled(uint64 readyAt);
    event Resumed();

    error InvalidConfiguration();
    error ProductionUnavailable();
    error Unauthorized();
    error StaleEmergency();
    error IsPaused();
    error DepositsClosed();
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
    error RegistryChanged();
    error CheckpointingUnavailable();
    error NotGracefullyClosable();

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
        bytes32 registryCodeHash = address(config.checkpointRegistry).codehash;
        if (
            address(config.token).code.length == 0 || address(config.verifier).code.length == 0
                || address(config.checkpointRegistry).code.length == 0
                || address(config.token) == address(config.verifier) || tokenHash == bytes32(0)
                || codeHash == bytes32(0) || registryCodeHash == bytes32(0)
                || address(config.checkpointRegistry) == address(config.token)
                || address(config.checkpointRegistry) == address(config.verifier) || config.domDomain == bytes32(0)
                || config.activationScheduleCommitment == bytes32(0) || config.governance.code.length == 0
                || config.guardian.code.length == 0 || config.guardian == config.governance
                || config.governance == address(config.token) || config.guardian == address(config.token)
                || config.governance == address(config.verifier) || config.guardian == address(config.verifier)
                || config.governance == address(config.checkpointRegistry)
                || config.guardian == address(config.checkpointRegistry)
                || config.withdrawalDelay < 6 hours || config.withdrawalDelay > 3 days
                || config.governanceDelay < 2 days || config.governanceDelay > 30 days || config.maxOutstanding == 0
                || config.outflowCapacity == 0 || config.outflowCapacity > config.maxOutstanding
        ) revert InvalidConfiguration();
        if (_tokenStaticWord(address(config.token), abi.encodeCall(IERC20Metadata.decimals, ())) != bytes32(uint256(6)))
        {
            revert UnsupportedToken();
        }

        bytes32 registryConfigHash = _registryStaticWord(
            address(config.checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.checkpointConfigHash, ())
        );
        if (
            registryConfigHash == bytes32(0)
                || _registryStaticWord(
                        address(config.checkpointRegistry),
                        abi.encodeCall(IDOMGracefulShutdownRegistry.bridgeDomain, ())
                    ) != config.domDomain
                || _registryStaticWord(
                        address(config.checkpointRegistry),
                        abi.encodeCall(IDOMGracefulShutdownRegistry.activationScheduleCommitment, ())
                    ) != config.activationScheduleCommitment
        ) revert InvalidConfiguration();

        bytes32 configHash = _readVerifierConfig(config.verifier);
        if (configHash == bytes32(0) || _readVerifierCapability(address(config.verifier)) != PROOF_ACCEPTED) {
            revert InvalidConfiguration();
        }
        address governanceImpl;
        bytes32 governanceImplHash;
        (governanceImpl, governanceImplHash, governanceOwnersCommitment) = _controlPlaneIdentity(config.governance);
        address guardianImpl;
        bytes32 guardianImplHash;
        (guardianImpl, guardianImplHash, guardianOwnersCommitment) = _controlPlaneIdentity(config.guardian);
        bytes32 governanceIdentityHash = _controlPlaneIdentityHash(
            config.governance,
            config.governance.codehash,
            governanceImpl,
            governanceImplHash,
            governanceOwnersCommitment
        );
        bytes32 guardianIdentityHash = _controlPlaneIdentityHash(
            config.guardian, config.guardian.codehash, guardianImpl, guardianImplHash, guardianOwnersCommitment
        );
        (bytes32 deploymentConfigHash, bytes32 preActivationConfigHash) = _reserveConfigurationHashes(
            config, tokenHash, codeHash, configHash, registryConfigHash, governanceIdentityHash, guardianIdentityHash
        );
        if (
            block.chainid == 1
                && (address(config.token) != ETHEREUM_USDT
                    || tokenHash != ETHEREUM_USDT_CODE_HASH
                    || PRODUCTION_VERIFIER_CODE_HASH == bytes32(0)
                    || PRODUCTION_VERIFIER_CONFIG_HASH == bytes32(0)
                    || PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH == bytes32(0)
                    || codeHash != PRODUCTION_VERIFIER_CODE_HASH
                    || configHash != PRODUCTION_VERIFIER_CONFIG_HASH
                    || preActivationConfigHash != PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH)
        ) revert ProductionUnavailable();

        token = config.token;
        tokenCodeHash = tokenHash;
        verifier = config.verifier;
        checkpointRegistry = config.checkpointRegistry;
        checkpointRegistryCodeHash = registryCodeHash;
        checkpointRegistryConfigHash = registryConfigHash;
        verifierCodeHash = codeHash;
        verifierConfigHash = configHash;
        reserveConfigHash = deploymentConfigHash;
        domDomain = config.domDomain;
        activationScheduleCommitment = config.activationScheduleCommitment;
        governance = config.governance;
        governanceCodeHash = config.governance.codehash;
        governanceImplementation = governanceImpl;
        governanceImplementationCodeHash = governanceImplHash;
        guardian = config.guardian;
        guardianCodeHash = config.guardian.codehash;
        guardianImplementation = guardianImpl;
        guardianImplementationCodeHash = guardianImplHash;
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
        // This relation is maintained by every release path. Keep the public
        // accounting surface fail-closed with a protocol error even if a future
        // maintenance change were to violate it, instead of exposing an opaque
        // arithmetic panic to queue and monitoring callers.
        if (totalReleased > totalDeposited) revert Insolvent();
        return totalDeposited - totalReleased;
    }

    /// @notice Reports the exact fail-closed control-plane predicate used by
    /// value paths and delayed resume, including Safe policy when applicable.
    function controlPlaneHealthy() external view returns (bool) {
        return _controlPlaneUnchanged(
            governance,
            governanceCodeHash,
            governanceImplementation,
            governanceImplementationCodeHash,
            governanceOwnersCommitment
        )
            && _controlPlaneUnchanged(
            guardian, guardianCodeHash, guardianImplementation, guardianImplementationCodeHash, guardianOwnersCommitment
        );
    }

    function unreservedCollateral() public view returns (uint256) {
        uint256 credited = outstanding();
        if (totalProvedDebtAmount > credited) revert Insolvent();
        return credited - totalProvedDebtAmount;
    }

    /// @notice Atomic queue header for off-chain monitoring. Consumers should
    /// pin all pagination calls to the same block tag as this snapshot.
    /// @return epoch Queue generation that must be supplied to every page.
    /// @return count Number of active pending withdrawals in this generation.
    /// @return amount Sum of the active pending withdrawal amounts.
    /// @return firstBurnId Head of the queue, or zero when the queue is empty.
    /// @return lastBurnId Tail of the queue, or zero when the queue is empty.
    function pendingQueueSnapshot()
        external
        view
        returns (uint64 epoch, uint256 count, uint256 amount, bytes32 firstBurnId, bytes32 lastBurnId)
    {
        return (queueEpoch, pendingCount, totalPendingAmount, firstPendingBurn, lastPendingBurn);
    }

    /// @notice Bounded traversal of the active queue. `cursor == 0` starts at
    /// the head; otherwise cursor is the first ID returned by this page.
    /// `nextCursor == 0` marks completion. A stale/unknown cursor fails closed.
    /// @dev Reverts on malformed headers, links, duplicates or count/end
    /// disagreement observed by this page. Performs no external calls. Use the
    /// same block tag for the snapshot and every page to avoid cross-block drift.
    /// @param expectedQueueEpoch Generation returned by pendingQueueSnapshot.
    /// @param cursor Zero for the head, or the prior page's nonzero nextCursor.
    /// @param maximum Maximum IDs to return, from one through MAX_PRUNE_BATCH.
    /// @return burnIds Active burn IDs beginning at cursor, in queue order.
    /// @return nextCursor Next ID to request, or zero after the declared tail.
    function pendingBurnPage(uint64 expectedQueueEpoch, bytes32 cursor, uint256 maximum)
        external
        view
        returns (bytes32[] memory burnIds, bytes32 nextCursor)
    {
        if (expectedQueueEpoch != queueEpoch) revert StaleEmergency();
        if (maximum == 0 || maximum > MAX_PRUNE_BATCH) revert InvalidConfiguration();
        uint256 queueCount = pendingCount;
        bytes32 firstBurnId = firstPendingBurn;
        bytes32 lastBurnId = lastPendingBurn;
        if (queueCount == 0) {
            if (
                firstBurnId != bytes32(0) || lastBurnId != bytes32(0) || totalPendingAmount != 0 || cursor != bytes32(0)
            ) revert PendingMismatch();
            return (new bytes32[](0), bytes32(0));
        }
        if (firstBurnId == bytes32(0) || lastBurnId == bytes32(0) || totalPendingAmount == 0) {
            revert PendingMismatch();
        }

        bool startedAtHead = cursor == bytes32(0);
        bytes32 burnId = startedAtHead ? firstBurnId : cursor;
        burnIds = new bytes32[](maximum);
        uint256 count = 0;
        bytes32 previousBurnId = bytes32(0);
        // Every failure below reports corrupted queue structure. Traversal is
        // hard-capped by MAX_PRUNE_BATCH, including when links form a cycle.
        // forge-lint: disable-start(require-revert-in-loop)
        while (count < maximum && burnId != bytes32(0)) {
            PendingWithdrawal storage pending = pendingWithdrawals[burnId];
            if (pending.statementHash == bytes32(0) || pending.queueEpoch != expectedQueueEpoch) {
                revert PendingMismatch();
            }

            if (count == 0) {
                if (burnId == firstBurnId) {
                    if (pending.previous != bytes32(0)) revert PendingMismatch();
                } else {
                    bytes32 predecessor = pending.previous;
                    PendingWithdrawal storage previous = pendingWithdrawals[predecessor];
                    if (
                        predecessor == bytes32(0) || previous.statementHash == bytes32(0)
                            || previous.queueEpoch != expectedQueueEpoch || previous.next != burnId
                    ) revert PendingMismatch();
                }
            } else if (pending.previous != previousBurnId) {
                revert PendingMismatch();
            }
            for (uint256 i; i < count; ++i) {
                if (burnIds[i] == burnId) revert PendingMismatch();
            }

            burnIds[count] = burnId;
            bytes32 followingBurnId = pending.next;
            if (followingBurnId == bytes32(0)) {
                if (burnId != lastBurnId) revert PendingMismatch();
            } else {
                PendingWithdrawal storage following = pendingWithdrawals[followingBurnId];
                if (
                    following.statementHash == bytes32(0) || following.queueEpoch != expectedQueueEpoch
                        || following.previous != burnId
                ) revert PendingMismatch();
            }
            previousBurnId = burnId;
            burnId = followingBurnId;
            ++count;
            if (startedAtHead && count == queueCount && burnId != bytes32(0)) revert PendingMismatch();
        }
        // forge-lint: disable-end(require-revert-in-loop)
        if (startedAtHead && burnId == bytes32(0) && count != queueCount) revert PendingMismatch();
        assembly ("memory-safe") {
            mstore(burnIds, count)
        }
        nextCursor = burnId;
    }

    function depositId(address funder, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), funder, salt));
    }

    function burnStatementHash(FinalizedBurn calldata burn) public view returns (bytes32) {
        return _burnHash(burn, 0);
    }

    function burnDebtHash(FinalizedBurn calldata burn) public view returns (bytes32) {
        return _burnHash(burn, 1);
    }

    /// @notice Hash of the exact withdrawal intent that native USDOM consensus
    /// must commit before block height/finality fields exist.
    function burnIntentHash(FinalizedBurn calldata burn) public view returns (bytes32) {
        return _burnHash(burn, 2);
    }

    /// @dev These are fixed-width ABI tuples with the same six-word prefix.
    /// One encoder preserves the declared field order while avoiding three
    /// independent ABI encoders in deployed runtime bytecode.
    function _burnHash(FinalizedBurn calldata burn, uint256 format) private view returns (bytes32 digest) {
        bytes32[14] memory encoded;
        encoded[0] = format == 0
            ? BURN_STATEMENT_TYPEHASH
            : (format == 1 ? BURN_DEBT_TYPEHASH : BURN_INTENT_TYPEHASH);
        encoded[1] = burn.burnId;
        encoded[2] = burn.requestId;
        encoded[3] = bytes32(uint256(uint160(burn.recipient)));
        encoded[4] = bytes32(uint256(burn.amount));
        encoded[5] = burn.domDomain;
        uint256 wordCount;
        if (format < 2) {
            encoded[6] = bytes32(uint256(burn.height));
            encoded[7] = burn.blockHash;
            encoded[8] = burn.stateRoot;
            if (format == 0) {
                encoded[9] = bytes32(uint256(burn.finalityBeaconSlot));
                encoded[10] = bytes32(uint256(burn.validUntil));
                encoded[11] = bytes32(block.chainid);
                encoded[12] = bytes32(uint256(uint160(address(this))));
                encoded[13] = activationScheduleCommitment;
                wordCount = 14;
            } else {
                encoded[9] = bytes32(uint256(burn.validUntil));
                encoded[10] = bytes32(block.chainid);
                encoded[11] = bytes32(uint256(uint160(address(this))));
                encoded[12] = activationScheduleCommitment;
                wordCount = 13;
            }
        } else {
            encoded[6] = bytes32(uint256(burn.validUntil));
            encoded[7] = bytes32(block.chainid);
            encoded[8] = bytes32(uint256(uint160(address(this))));
            wordCount = 9;
        }
        assembly ("memory-safe") {
            digest := keccak256(encoded, shl(5, wordCount))
        }
    }

    function deposit(uint64 amount, bytes32 salt, bytes32 receivingCommitment)
        external
        nonReentrant
        whenNotPaused
        returns (bytes32 id)
    {
        if (depositsClosed) revert DepositsClosed();
        if (amount == 0 || receivingCommitment == bytes32(0) || uint256(receivingCommitment) >= BN254_SCALAR_FIELD) {
            revert InvalidDeposit();
        }
        // Never accept new collateral after the immutable finality registry has
        // halted or native issuance has closed. Existing proved burn debts stay
        // payable through queue renewal and execution below.
        _requireCheckpointIngressOpen();
        _requireVerifierUnchanged();
        _requireTokenUsable(msg.sender, address(this));
        if (outstanding() + amount > maxOutstanding) revert ExposureLimit();
        id = depositId(msg.sender, salt);
        if (deposits[id].funder != address(0)) revert AlreadyUsed();
        uint256 reserveBefore = _tokenBalanceOf(address(this));
        if (reserveBefore < outstanding()) revert Insolvent();
        uint256 funderBefore = _tokenBalanceOf(msg.sender);
        deposits[id] = Deposit(msg.sender, amount, receivingCommitment);
        totalDeposited += amount;
        _callToken(abi.encodeCall(IERC20.transferFrom, (msg.sender, address(this), amount)));
        // Exact deltas deliberately reject fee-on-transfer, rebasing and other
        // collateral semantics that would break one-to-one accounting.
        if (
            _tokenBalanceOf(address(this)) != reserveBefore + amount
                || _tokenBalanceOf(msg.sender) + amount != funderBefore
        ) revert UnsupportedToken();
        // The non-reentrant transfer and exact postcondition precede this log;
        // any callback or failed postcondition reverts the complete transaction.
        // forge-lint: disable-next-line(reentrancy-events)
        emit Deposited(id, msg.sender, amount, receivingCommitment);
    }

    /// @notice Every queue lease verifies its complete statement before collateral
    /// is reserved. Execution later consumes that lease's exact statement hash.
    function queueWithdrawal(FinalizedBurn calldata burn, bytes calldata proof) external nonReentrant whenNotPaused {
        if (
            burn.burnId == bytes32(0) || burn.requestId == bytes32(0) || burn.recipient == address(0)
                || burn.recipient == address(this) || burn.recipient == address(token) || burn.amount == 0
                || burn.domDomain != domDomain || burn.height == 0 || burn.blockHash == bytes32(0)
                || burn.stateRoot == bytes32(0) || burn.finalityBeaconSlot == 0 || burn.validUntil == 0
                || proof.length != EVM_PROOF_BYTES || bytes4(proof[:4]) != RISC_ZERO_GROTH16_V3_SELECTOR
        ) revert InvalidBurn();
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
        bytes32 statementHash = burnStatementHash(burn);
        bytes32 provedStatement = provedBurnStatements[burn.burnId];
        bytes32 debtHash = burnDebtHash(burn);
        bytes32 provedDebt = provedBurnDebts[burn.burnId];
        bytes32 provedRequestBurn = provedRequestBurns[burn.requestId];
        uint64 provedFinalitySlot = provedBurnFinalitySlots[burn.burnId];
        bool renewal = provedStatement != bytes32(0);
        // Permanent ingress closure also prevents a first proof from creating a
        // new collateral debt. Existing proved debts may renew their queue lease
        // and remain payable after a controlled resume.
        if (depositsClosed && !renewal) revert DepositsClosed();
        if (renewal) {
            // The original proof/finality admission is permanent. A stale
            // Beacon slot may advance under a new proof of the exact same debt;
            // every other public field and the burn/request pairing is immutable.
            if (
                provedDebt != debtHash || provedRequestBurn != burn.burnId
                    || burn.finalityBeaconSlot < provedFinalitySlot
            ) revert AlreadyUsed();
            _requireRecentFinalitySlot(burn.finalityBeaconSlot);
        } else {
            if (provedRequestBurn != bytes32(0)) revert AlreadyUsed();
            _requireRecentFinalitySlot(burn.finalityBeaconSlot);
            // The first accepted proof creates an irreversible collateral debt.
            // Bind that transition to the exact checkpoint registry selected at
            // deployment. Later registry failure must not strand an already
            // proved debt, so renewals and settlement intentionally skip this
            // dependency check.
            _requireCheckpointRegistryUnchanged();
        }
        PendingWithdrawal storage existing = pendingWithdrawals[burn.burnId];
        if (
            paidBurns[burn.burnId] || paidRequests[burn.requestId]
                || (existing.statementHash != bytes32(0) && existing.queueEpoch == queueEpoch)
                || _hasActivePendingRequest(burn.requestId)
        ) revert AlreadyUsed();

        // Terminal statement/replay errors above are entirely local. Probe the
        // external token only once the request is structurally admissible.
        // Recipient blacklisting must not suppress recognition of an already
        // irreversible native burn debt. Reserve the debt while the reserve
        // account and token policy are usable; execution separately requires
        // the exact recipient to be transferable before any value moves.
        _requireTokenUsable(address(this), address(this));
        // The first accepted proof creates an irreversible reserve debt. A
        // renewal only restores its queue lease and must not reserve the same
        // collateral twice. Expiry, pruning and emergency pause release queue
        // storage, never this permanent economic obligation.
        if ((!renewal && burn.amount > unreservedCollateral()) || _tokenBalanceOf(address(this)) < outstanding()) {
            revert Insolvent();
        }
        _verify(statementHash, proof);
        if (!renewal) {
            provedBurnStatements[burn.burnId] = statementHash;
            provedBurnDebts[burn.burnId] = debtHash;
            provedRequestBurns[burn.requestId] = burn.burnId;
            totalProvedDebtAmount += burn.amount;
        }
        provedBurnFinalitySlots[burn.burnId] = burn.finalityBeaconSlot;
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
        _emitWithdrawalLease(burn, statementHash, readyAt, expiresAt, renewal);
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
        uint256 reserveBefore = _tokenBalanceOf(address(this));
        if (reserveBefore < credited) revert Insolvent();
        // Revalidate the permanent debt record immediately before consuming its
        // aggregate reservation. The queued statement already binds every burn
        // field, but these independent checks prevent a later maintenance bug
        // from reducing one debt on behalf of another or an older renewal slot.
        if (
            totalProvedDebtAmount < burn.amount || provedBurnDebts[burn.burnId] != burnDebtHash(burn)
                || provedRequestBurns[burn.requestId] != burn.burnId
                || provedBurnFinalitySlots[burn.burnId] != burn.finalityBeaconSlot
        ) revert PendingMismatch();
        uint256 recipientBefore = _tokenBalanceOf(burn.recipient);

        bucketBalance = _checkedUint64(available - burn.amount);
        bucketUpdatedAt = _checkedUint64(block.timestamp);
        totalReleased += burn.amount;
        totalProvedDebtAmount -= burn.amount;
        paidBurns[burn.burnId] = true;
        paidRequests[burn.requestId] = true;
        _removePending(burn.burnId, pending);

        _callToken(abi.encodeCall(IERC20.transfer, (burn.recipient, burn.amount)));
        // Exact deltas are a required USDT collateral invariant, not a generic
        // ERC-20 compatibility assumption.
        if (
            _tokenBalanceOf(address(this)) + burn.amount != reserveBefore
                || _tokenBalanceOf(burn.recipient) != recipientBefore + burn.amount
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
        _emitProvedDebtSettled(burn, pending.queueEpoch);
    }

    function discardWithdrawal(bytes32 burnId) external nonReentrant {
        PendingWithdrawal memory pending = pendingWithdrawals[burnId];
        if (pending.statementHash == bytes32(0)) revert PendingMismatch();
        // forge-lint: disable-next-line(block-timestamp)
        if (pending.queueEpoch == queueEpoch && block.timestamp <= pending.expiresAt) revert StillValid();
        _removePending(burnId, pending);
        _emitWithdrawalDiscarded(burnId, pending);
    }

    function pruneExpired(uint256 maximum) external nonReentrant returns (uint256 removed) {
        if (maximum == 0 || maximum > MAX_PRUNE_BATCH) revert InvalidConfiguration();
        while (removed < maximum && firstPendingBurn != bytes32(0)) {
            bytes32 burnId = firstPendingBurn;
            PendingWithdrawal memory pending = pendingWithdrawals[burnId];
            if (
                pending.statementHash == bytes32(0) || pending.queueEpoch != queueEpoch
                    || pending.previous != bytes32(0)
            ) revert PendingMismatch();
            // forge-lint: disable-next-line(block-timestamp)
            if (block.timestamp <= pending.expiresAt) break;
            _removePending(burnId, pending);
            _emitWithdrawalDiscarded(burnId, pending);
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
            _emitWithdrawalDiscarded(burnId, pending);
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

    /// @notice Mark the reserve terminal only after the pinned checkpoint
    /// registry proves native issuance closure and zero circulation, and after
    /// all Ethereum collateral liabilities have actually been paid.
    function finalizeGracefulShutdown() external nonReentrant {
        if (gracefullyShutdown) revert NotGracefullyClosable();
        if (
            !depositsClosed || paused || totalDeposited != totalReleased || outstanding() != 0
                || totalProvedDebtAmount != 0 || pendingCount != 0 || totalPendingAmount != 0
                || firstPendingBurn != bytes32(0) || lastPendingBurn != bytes32(0)
        ) revert NotGracefullyClosable();
        _requireControlPlaneUnchanged();
        _requireCheckpointRegistryUnchanged();
        bytes32 shutdownWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.gracefullyShutdown, ())
        );
        bytes32 closureWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.latestIssuanceClosed, ())
        );
        bytes32 issuedWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.latestTotalIssued, ())
        );
        bytes32 burnedWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.latestTotalBurned, ())
        );
        if (uint256(shutdownWord) > 1 || uint256(closureWord) > 1) revert RegistryChanged();
        if (
            shutdownWord != bytes32(uint256(1)) || closureWord != bytes32(uint256(1))
                // Native closure authenticates the reserve's cumulative deposit
                // total. Require that cross-domain equality here as well as zero
                // native circulation, so two internally balanced but unrelated
                // ledgers can never jointly authorize terminal shutdown.
                || issuedWord != bytes32(totalDeposited) || burnedWord != issuedWord
        ) {
            revert NotGracefullyClosable();
        }
        gracefullyShutdown = true;
        // Registry and identity interactions above are bounded STATICCALLs;
        // static context cannot mutate or reenter before this terminal event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit GracefullyShutdown(address(checkpointRegistry), checkpointRegistryConfigHash, totalReleased);
    }

    function pause() external {
        _pause();
    }

    /// @notice Permanently stop new collateral ingress without pausing proof
    /// renewal or payout of debts already created by native consensus.
    function closeDeposits() external {
        _requireEmergencyAuthority();
        _requireControlPlaneUnchanged();
        if (depositsClosed) revert DepositsClosed();
        depositsClosed = true;
        // The preceding control-plane probe is STATICCALL-only and cannot
        // reorder either irreversible closure event through stateful reentry.
        // forge-lint: disable-start(reentrancy-events)
        emit DepositsPermanentlyClosed(msg.sender);
        emit DepositsClosedV2(totalDeposited, reserveConfigHash, activationScheduleCommitment, domDomain);
        // forge-lint: disable-end(reentrancy-events)
    }

    /// @notice Automation stop bound to the queue generation it inspected. A
    /// delayed transaction cannot invalidate a reviewed replacement queue.
    function pauseQueueEpoch(uint64 expectedQueueEpoch) external {
        _requireEmergencyAuthority();
        if (expectedQueueEpoch != queueEpoch) revert StaleEmergency();
        _pauseState();
    }

    function _pause() private {
        _requireEmergencyAuthority();
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
        // The preceding control-plane probes are STATICCALL-only and cannot
        // mutate state or reenter before this authorization event.
        // forge-lint: disable-next-item(reentrancy-events)
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

    function _emitWithdrawalLease(
        FinalizedBurn calldata burn,
        bytes32 statementHash,
        uint64 readyAt,
        uint64 expiresAt,
        bool renewal
    ) private {
        emit WithdrawalLeaseV2(
            burn.burnId,
            burn.requestId,
            burn.amount,
            queueEpoch,
            statementHash,
            readyAt,
            expiresAt,
            burn.finalityBeaconSlot,
            renewal
        );
    }

    function _emitProvedDebtSettled(FinalizedBurn calldata burn, uint64 leaseEpoch) private {
        emit ProvedDebtSettled(burn.burnId, burn.requestId, burn.amount, leaseEpoch, totalProvedDebtAmount);
    }

    function _emitWithdrawalDiscarded(bytes32 burnId, PendingWithdrawal memory pending) private {
        emit WithdrawalDiscarded(burnId, pending.requestId);
        emit WithdrawalDiscardedV2(burnId, pending.requestId, pending.amount, pending.queueEpoch);
    }

    function _requireEmergencyAuthority() private view {
        if (msg.sender != guardian && msg.sender != governance) revert Unauthorized();
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

    /// @dev A nonzero configuration hash alone does not identify the verifier
    /// capability. Require the finalized-burn acceptance domain before this
    /// deployment can admit collateral behind the wrong proof flow.
    function _readVerifierCapability(address verifierAddress) private view returns (bytes32 value) {
        (bool ok, bytes32 result) =
            _staticcallWord(verifierAddress, VERIFIER_GAS_LIMIT, abi.encodeWithSignature("PROOF_ACCEPTED()"));
        if (ok) value = result;
    }

    function _requireVerifierUnchanged() private view {
        if (
            address(verifier).codehash != verifierCodeHash || _readVerifierConfig(verifier) != verifierConfigHash
                || _readVerifierCapability(address(verifier)) != PROOF_ACCEPTED
        ) {
            revert VerifierChanged();
        }
    }

    function _requireCheckpointRegistryUnchanged() private view {
        if (
            address(checkpointRegistry).codehash != checkpointRegistryCodeHash
                || _registryStaticWord(
                        address(checkpointRegistry),
                        abi.encodeCall(IDOMGracefulShutdownRegistry.checkpointConfigHash, ())
                    ) != checkpointRegistryConfigHash
                || _registryStaticWord(
                        address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.bridgeDomain, ())
                    ) != domDomain
                || _registryStaticWord(
                        address(checkpointRegistry),
                        abi.encodeCall(IDOMGracefulShutdownRegistry.activationScheduleCommitment, ())
                    ) != activationScheduleCommitment
        ) revert RegistryChanged();
    }

    function _requireCheckpointIngressOpen() private view {
        _requireCheckpointRegistryUnchanged();
        bytes32 haltedWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.halted, ())
        );
        bytes32 shutdownWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.gracefullyShutdown, ())
        );
        bytes32 issuanceClosedWord = _registryStaticWord(
            address(checkpointRegistry), abi.encodeCall(IDOMGracefulShutdownRegistry.latestIssuanceClosed, ())
        );
        if (uint256(haltedWord) > 1 || uint256(shutdownWord) > 1 || uint256(issuanceClosedWord) > 1) {
            revert RegistryChanged();
        }
        if (haltedWord != bytes32(0) || shutdownWord != bytes32(0) || issuanceClosedWord != bytes32(0)) {
            revert CheckpointingUnavailable();
        }
    }

    function _requireControlPlaneUnchanged() private view {
        if (
            !_controlPlaneUnchanged(
                    governance,
                    governanceCodeHash,
                    governanceImplementation,
                    governanceImplementationCodeHash,
                    governanceOwnersCommitment
                )
                || !_controlPlaneUnchanged(
                    guardian,
                    guardianCodeHash,
                    guardianImplementation,
                    guardianImplementationCodeHash,
                    guardianOwnersCommitment
                )
        ) {
            revert ControlPlaneChanged();
        }
    }

    function _reserveConfigurationHashes(
        Config memory config,
        bytes32 tokenHash,
        bytes32 verifierHash,
        bytes32 verifierConfiguration,
        bytes32 registryConfiguration,
        bytes32 governanceIdentityHash,
        bytes32 guardianIdentityHash
    ) private view returns (bytes32 deploymentHash, bytes32 preActivationHash) {
        bytes32 policyHash = _reservePolicyHash(config, governanceIdentityHash, guardianIdentityHash);
        deploymentHash = keccak256(
            abi.encode(
                RESERVE_CONFIG_TYPEHASH,
                _reserveIdentityHash(config, tokenHash, verifierHash, verifierConfiguration, registryConfiguration),
                policyHash
            )
        );
        preActivationHash = keccak256(
            abi.encode(
                RESERVE_PREACTIVATION_CONFIG_TYPEHASH,
                _reservePreActivationIdentityHash(
                    config, tokenHash, verifierHash, verifierConfiguration, registryConfiguration
                ),
                policyHash
            )
        );
    }

    function _reserveIdentityHash(
        Config memory config,
        bytes32 tokenHash,
        bytes32 codeHash,
        bytes32 configHash,
        bytes32 registryConfiguration
    ) private view returns (bytes32) {
        bytes memory prefix = abi.encode(
            RESERVE_IDENTITY_TYPEHASH,
            block.chainid,
            address(this),
            address(config.token),
            tokenHash,
            address(config.verifier),
            codeHash,
            configHash
        );
        return keccak256(
            bytes.concat(
                prefix,
                abi.encode(
                    address(config.checkpointRegistry),
                    address(config.checkpointRegistry).codehash,
                    registryConfiguration,
                    config.domDomain,
                    config.activationScheduleCommitment
                )
            )
        );
    }

    function _reservePreActivationIdentityHash(
        Config memory config,
        bytes32 tokenHash,
        bytes32 codeHash,
        bytes32 configHash,
        bytes32 registryConfiguration
    ) private view returns (bytes32) {
        bytes memory prefix = abi.encode(
            RESERVE_PREACTIVATION_IDENTITY_TYPEHASH,
            block.chainid,
            address(this),
            address(config.token),
            tokenHash,
            address(config.verifier),
            codeHash,
            configHash
        );
        return keccak256(
            bytes.concat(
                prefix,
                abi.encode(
                    address(config.checkpointRegistry),
                    address(config.checkpointRegistry).codehash,
                    registryConfiguration,
                    config.domDomain
                )
            )
        );
    }

    function _reservePolicyHash(Config memory config, bytes32 governanceIdentityHash, bytes32 guardianIdentityHash)
        private
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                RESERVE_POLICY_TYPEHASH,
                governanceIdentityHash,
                guardianIdentityHash,
                config.withdrawalDelay,
                config.governanceDelay,
                config.maxOutstanding,
                config.outflowCapacity
            )
        );
    }

    function _controlPlaneIdentityHash(
        address account,
        bytes32 accountCodeHash,
        address implementation,
        bytes32 implementationCodeHash,
        bytes32 ownersCommitment
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CONTROL_PLANE_IDENTITY_TYPEHASH,
                account,
                accountCodeHash,
                implementation,
                implementationCodeHash,
                ownersCommitment
            )
        );
    }

    /// @dev SafeProxy exposes its slot-zero singleton through masterCopy().
    /// Direct contracts that do not implement that selector are bound to their
    /// own runtime identity. A proxy that returns malformed or undeployed state
    /// is rejected rather than silently treated as a direct contract.
    function _controlPlaneIdentity(address account)
        private
        view
        returns (address implementation, bytes32 codeHash, bytes32 ownersCommitment)
    {
        (bool ok, bytes32 word) = _staticcallWord(account, CONTROL_PLANE_GAS_LIMIT, hex"a619486e");
        if (!ok) {
            if (block.chainid == 1) revert InvalidConfiguration();
            return (account, account.codehash, bytes32(0));
        }
        if (uint256(word) > type(uint160).max) revert InvalidConfiguration();
        implementation = address(uint160(uint256(word)));
        codeHash = implementation.codehash;
        if (implementation == address(0) || implementation == account || codeHash == bytes32(0)) {
            revert InvalidConfiguration();
        }
        if (
            block.chainid == 1
                && (account.codehash != SAFE_MAINNET_PROXY_CODE_HASH || implementation != SAFE_MAINNET_SINGLETON
                    || codeHash != SAFE_MAINNET_SINGLETON_CODE_HASH)
        ) revert InvalidConfiguration();
        if (!_safePolicyIntact(account)) revert InvalidConfiguration();
        (bool ownersIntact, bytes32 currentOwnersCommitment) = _safeOwnersIdentity(account);
        if (!ownersIntact) revert InvalidConfiguration();
        ownersCommitment = currentOwnersCommitment;
    }

    function _controlPlaneUnchanged(
        address account,
        bytes32 accountCodeHash,
        address implementation,
        bytes32 implementationCodeHash,
        bytes32 ownersCommitment
    ) private view returns (bool) {
        if (account.codehash != accountCodeHash) return false;
        if (implementation == account) return implementation.codehash == implementationCodeHash;
        (bool ok, bytes32 word) = _staticcallWord(account, CONTROL_PLANE_GAS_LIMIT, hex"a619486e");
        (bool ownersIntact, bytes32 currentOwnersCommitment) = _safeOwnersIdentity(account);
        return ok && uint256(word) <= type(uint160).max && address(uint160(uint256(word))) == implementation
            && implementation.codehash == implementationCodeHash && _safePolicyIntact(account) && ownersIntact
            && currentOwnersCommitment == ownersCommitment;
    }

    function _safePolicyIntact(address account) private view returns (bool) {
        (bool thresholdOk, bytes32 thresholdWord) = _staticcallWord(account, CONTROL_PLANE_GAS_LIMIT, hex"e75235b8");
        return thresholdOk && uint256(thresholdWord) == CONTROL_PLANE_THRESHOLD && _safeOwnersIntact(account)
            && _safeModulesEmpty(account) && _safeGuardEmpty(account)
            && (block.chainid != 1 || _safeFallbackHandlerIntact(account));
    }

    /// @dev Accepts only the canonical ABI return for exactly three distinct,
    /// nonzero owners. Return data is copied into five fixed words.
    function _safeOwnersIntact(address account) private view returns (bool intact) {
        (intact,) = _safeOwnersIdentity(account);
    }

    /// @dev Safe's linked-list order is not an authority property. Commit to the
    /// canonical sorted owner set so remove/re-add ordering cannot strand funds,
    /// while any actual owner replacement still changes the identity.
    function _safeOwnersIdentity(address account) private view returns (bool intact, bytes32 commitment) {
        bytes memory callData = hex"a0e67e2b";
        bytes32 offset;
        bytes32 count;
        bytes32 first;
        bytes32 second;
        bytes32 third;
        uint256 returnSize;
        assembly ("memory-safe") {
            let output := mload(0x40)
            intact := staticcall(CONTROL_PLANE_GAS_LIMIT, account, add(callData, 32), mload(callData), output, 160)
            returnSize := returndatasize()
            offset := mload(output)
            count := mload(add(output, 32))
            first := mload(add(output, 64))
            second := mload(add(output, 96))
            third := mload(add(output, 128))
        }
        address firstOwner = address(uint160(uint256(first)));
        address secondOwner = address(uint160(uint256(second)));
        address thirdOwner = address(uint160(uint256(third)));
        intact = intact && returnSize == 160 && uint256(offset) == 32 && uint256(count) == CONTROL_PLANE_OWNER_COUNT
            && uint256(first) <= type(uint160).max && uint256(second) <= type(uint160).max
            && uint256(third) <= type(uint160).max && first != bytes32(0) && second != bytes32(0) && third != bytes32(0)
            && first != second && first != third && second != third && firstOwner != address(1)
            && secondOwner != address(1) && thirdOwner != address(1) && firstOwner != account && secondOwner != account
            && thirdOwner != account && firstOwner.code.length == 0 && secondOwner.code.length == 0
            && thirdOwner.code.length == 0;
        if (intact) commitment = _canonicalOwnerSetCommitment(firstOwner, secondOwner, thirdOwner);
    }

    function _canonicalOwnerSetCommitment(address first, address second, address third) private pure returns (bytes32) {
        if (second < first) (first, second) = (second, first);
        if (third < second) (second, third) = (third, second);
        if (second < first) (first, second) = (second, first);
        return keccak256(abi.encode(first, second, third));
    }

    /// @dev Safe encodes (address[] empty,address next=sentinel) as exactly
    /// three words: offset 0x40, sentinel 0x1, array length zero.
    function _safeModulesEmpty(address account) private view returns (bool empty) {
        bytes memory callData = abi.encodeWithSelector(bytes4(0xcc2f8452), address(1), uint256(1));
        bytes32 offset;
        bytes32 next;
        bytes32 count;
        uint256 returnSize;
        assembly ("memory-safe") {
            let output := mload(0x40)
            empty := staticcall(CONTROL_PLANE_GAS_LIMIT, account, add(callData, 32), mload(callData), output, 96)
            returnSize := returndatasize()
            offset := mload(output)
            next := mload(add(output, 32))
            count := mload(add(output, 64))
        }
        empty = empty && returnSize == 96 && uint256(offset) == 64 && uint256(next) == 1 && count == bytes32(0);
    }

    /// @dev Safe v1.4.1 exposes arbitrary storage through getStorageAt(). One
    /// guard slot is encoded as ABI bytes: offset 0x20, length 0x20, zero word.
    function _safeGuardEmpty(address account) private view returns (bool empty) {
        (bool intact, bytes32 guard) = _safeStorageWord(account, SAFE_GUARD_STORAGE_SLOT);
        empty = intact && guard == bytes32(0);
    }

    function _safeFallbackHandlerIntact(address account) private view returns (bool intact) {
        bytes32 handler;
        (intact, handler) = _safeStorageWord(account, SAFE_FALLBACK_HANDLER_STORAGE_SLOT);
        intact = intact && uint256(handler) <= type(uint160).max
            && address(uint160(uint256(handler))) == SAFE_MAINNET_FALLBACK_HANDLER
            && SAFE_MAINNET_FALLBACK_HANDLER.codehash == SAFE_MAINNET_FALLBACK_HANDLER_CODE_HASH;
    }

    /// @dev Safe encodes one storage word as ABI bytes: offset 0x20, length
    /// 0x20, then the word. Both guard and fallback-handler checks consume this
    /// exact canonical response, so sharing the bounded decoder loses no check.
    function _safeStorageWord(address account, uint256 slot) private view returns (bool intact, bytes32 value) {
        bytes memory callData = abi.encodeWithSelector(SAFE_GET_STORAGE_AT_SELECTOR, slot, uint256(1));
        bytes32 offset;
        bytes32 length;
        uint256 returnSize;
        assembly ("memory-safe") {
            let output := mload(0x40)
            intact := staticcall(CONTROL_PLANE_GAS_LIMIT, account, add(callData, 32), mload(callData), output, 96)
            returnSize := returndatasize()
            offset := mload(output)
            length := mload(add(output, 32))
            value := mload(add(output, 64))
        }
        intact = intact && returnSize == 96 && uint256(offset) == 32 && uint256(length) == 32;
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
            // Validate the complete local splice before arithmetic or writes.
            // This turns any impossible accounting/link divergence into the
            // protocol error instead of an underflow panic or silent orphan.
            if (pendingCount == 0 || totalPendingAmount < pending.amount) revert PendingMismatch();
            if (pending.previous == bytes32(0)) {
                if (firstPendingBurn != burnId) revert PendingMismatch();
            } else {
                PendingWithdrawal storage previous = pendingWithdrawals[pending.previous];
                if (previous.queueEpoch != queueEpoch || previous.next != burnId) revert PendingMismatch();
            }
            if (pending.next == bytes32(0)) {
                if (lastPendingBurn != burnId) revert PendingMismatch();
            } else {
                PendingWithdrawal storage following = pendingWithdrawals[pending.next];
                if (following.queueEpoch != queueEpoch || following.previous != burnId) revert PendingMismatch();
            }
            if (pending.previous == bytes32(0)) firstPendingBurn = pending.next;
            else pendingWithdrawals[pending.previous].next = pending.next;
            if (pending.next == bytes32(0)) lastPendingBurn = pending.previous;
            else pendingWithdrawals[pending.next].previous = pending.previous;
            totalPendingAmount -= pending.amount;
            --pendingCount;
        } else {
            // Old generations are intentionally unlinked in O(1). They may be
            // deleted lazily, but an entry still referenced by either current
            // header or a current-generation neighbor is corruption, not an
            // old lease, and must never be silently removed.
            if (firstPendingBurn == burnId || lastPendingBurn == burnId) revert PendingMismatch();
            if (pending.previous != bytes32(0)) {
                PendingWithdrawal storage previous = pendingWithdrawals[pending.previous];
                if (previous.queueEpoch == queueEpoch && previous.next == burnId) revert PendingMismatch();
            }
            if (pending.next != bytes32(0)) {
                PendingWithdrawal storage following = pendingWithdrawals[pending.next];
                if (following.queueEpoch == queueEpoch && following.previous == burnId) revert PendingMismatch();
            }
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
        address target = address(token);
        if (
            _tokenBool(target, abi.encodeCall(IUSDTPolicy.paused, ()))
                || _tokenBool(target, abi.encodeCall(IUSDTPolicy.deprecated, ()))
                || _tokenStaticWord(target, abi.encodeCall(IUSDTPolicy.upgradedAddress, ())) != bytes32(0)
                || _tokenStaticWord(target, abi.encodeCall(IUSDTPolicy.basisPointsRate, ())) != bytes32(0)
                || _tokenStaticWord(target, abi.encodeCall(IUSDTPolicy.maximumFee, ())) != bytes32(0)
        ) revert UnsafeTokenState();
        if (_tokenBool(target, abi.encodeCall(IUSDTPolicy.isBlackListed, (from)))) revert FrozenTokenAccount(from);
        if (to != from && _tokenBool(target, abi.encodeCall(IUSDTPolicy.isBlackListed, (to)))) {
            revert FrozenTokenAccount(to);
        }
    }

    function _tokenBool(address target, bytes memory callData) private view returns (bool value) {
        bytes32 word = _tokenStaticWord(target, callData);
        if (uint256(word) > 1) revert UnsupportedToken();
        value = word == bytes32(uint256(1));
    }

    /// @dev Bound both gas and copied returndata from the externally controlled
    /// ERC-20 boundary. Canonical uint256 ABI is exactly one word.
    function _tokenBalanceOf(address account) private view returns (uint256) {
        return uint256(_tokenStaticWord(address(token), abi.encodeCall(IERC20.balanceOf, (account))));
    }

    function _registryStaticWord(address target, bytes memory callData) private view returns (bytes32 word) {
        (bool ok, bytes32 result) = _staticcallWord(target, REGISTRY_GAS_LIMIT, callData);
        if (!ok) revert RegistryChanged();
        word = result;
    }

    function _tokenStaticWord(address target, bytes memory callData) private view returns (bytes32 word) {
        (bool ok, bytes32 result) = _staticcallWord(target, TOKEN_GAS_LIMIT, callData);
        if (!ok) revert UnsupportedToken();
        word = result;
    }

    /// @dev USDT historically returns no value. Accept either no returndata or
    /// canonical `true`, while rejecting false, malformed and oversized output
    /// without copying attacker-selected returndata.
    function _callToken(bytes memory callData) private {
        address target = address(token);
        bool ok;
        uint256 returnSize;
        bytes32 result;
        assembly ("memory-safe") {
            let output := mload(0x40)
            ok := call(TOKEN_GAS_LIMIT, target, 0, add(callData, 32), mload(callData), output, 32)
            returnSize := returndatasize()
            result := mload(output)
        }
        if (!ok || (returnSize != 0 && (returnSize != 32 || result != bytes32(uint256(1))))) {
            revert UnsupportedToken();
        }
    }

    function _timestampAfter(uint256 delay) private view returns (uint64) {
        if (delay > type(uint64).max || block.timestamp > type(uint64).max - delay) revert TimestampOverflow();
        return _checkedUint64(block.timestamp + delay);
    }

    function _checkedUint64(uint256 value) private pure returns (uint64) {
        if (value > type(uint64).max) revert TimestampOverflow();
        // The explicit bound above proves that this narrowing conversion cannot truncate.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(value);
    }
}
