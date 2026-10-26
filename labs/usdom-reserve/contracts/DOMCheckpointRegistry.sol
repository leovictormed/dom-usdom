// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice A verifier implementation must prove that `statementHash` names a
/// valid DOM consensus extension from the previous checkpoint to the proposed
/// checkpoint. Returning any value other than `PROOF_ACCEPTED` is rejection.
interface IDOMCheckpointVerifier {
    function verifierConfigHash() external view returns (bytes32);
    function verifyDOMCheckpoint(bytes32 statementHash, bytes calldata proof) external view returns (bytes32);
}

/// @title Immutable, delayed work-selected DOM checkpoint registry
/// @notice Permissionless relayers compete with proof-authorized candidates at
/// fixed heights. Only the highest-work candidate after a challenge window is
/// finalized. The registry has no upgrade, verifier rotation or arbitrary call.
contract DOMCheckpointRegistry {
    /// @notice Canonical RISC Zero Groth16 EVM seal: selector plus eight BN254 words.
    bytes4 private constant RISC_ZERO_GROTH16_V3_SELECTOR = 0x73c457ba;
    uint256 public constant EVM_PROOF_BYTES = 4 + 8 * 32;
    uint256 public constant MAX_PROOF_BYTES = EVM_PROOF_BYTES;
    uint256 public constant VERIFIER_GAS_LIMIT = 5_000_000;
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
    uint256 public constant MAX_CHECKPOINT_INTERVAL = 360;
    uint256 public constant MIN_CHALLENGE_PERIOD = 1 days;
    uint256 public constant MAX_CHALLENGE_PERIOD = 30 days;
    bytes32 public constant PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V3");
    uint16 public constant NATIVE_STATE_VERSION = 3;
    uint16 public constant TRANSITION_BATCH_VERSION = 4;
    bytes32 public constant LEGACY_CHECKPOINT_STATEMENT_TYPEHASH = keccak256(
        "DOMCheckpoint(bytes32 bridgeDomain,uint32 domNetworkMagic,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)"
    );
    bytes32 public constant CHECKPOINT_STATEMENT_TYPEHASH = keccak256(
        "DOMCheckpointV4(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)"
    );
    bytes32 public constant CHECKPOINT_IDENTITY_TYPEHASH = keccak256(
        "DOMCheckpointIdentity(uint256 ethereumChainId,address registry,bytes32 bridgeDomain,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,uint32 checkpointInterval,uint32 confirmationDepth,uint64 challengePeriod,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash)"
    );
    bytes32 public constant CONTROL_PLANE_IDENTITY_TYPEHASH = keccak256(
        "ControlPlaneIdentity(address account,bytes32 accountCodeHash,address implementation,bytes32 implementationCodeHash,bytes32 ownersCommitment)"
    );
    bytes32 public constant CHECKPOINT_BOOTSTRAP_TYPEHASH = keccak256(
        "DOMCheckpointBootstrap(bytes32 guardianIdentityHash,uint64 initialHeight,bytes32 initialBlock,bytes32 initialContextHash,uint256 initialTotalDifficulty)"
    );
    bytes32 public constant CHECKPOINT_CONFIG_TYPEHASH =
        keccak256("DOMCheckpointConfig(bytes32 identityHash,bytes32 bootstrapHash)");

    // A production release must pin both verifier values from independently
    // built artifacts. The release-specific registry identity remains in slot
    // zero; compiling it into runtime would make native activation circular.
    bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_CHECKPOINT_CONFIG_HASH = bytes32(0);

    bytes32 public immutable bridgeDomain;
    uint32 public immutable domNetworkMagic;
    bytes32 public immutable domChainId;
    uint64 public immutable firstV4Height;
    uint32 public immutable checkpointInterval;
    uint32 public immutable confirmationDepth;
    uint64 public immutable challengePeriod;
    IDOMCheckpointVerifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable verifierConfigHash;
    address public immutable guardian;
    bytes32 public immutable guardianCodeHash;
    address public immutable guardianImplementation;
    bytes32 public immutable guardianImplementationCodeHash;
    bytes32 public immutable guardianOwnersCommitment;

    // Deliberately the first storage variable. Ethereum witnesses authenticate
    // slot zero and the Rust policy additionally pins this contract's code hash.
    bytes32 public checkpointConfigHash;
    /// @notice Kept outside runtime bytecode to make the runtime identity
    /// derivable before this native activation commitment exists.
    bytes32 public activationScheduleCommitment;
    bytes32 public activationEmptyStateRoot;
    uint64 public latestHeight;
    uint64 public checkpointCount;
    bool public halted;
    /// @notice Proof-authorized terminal state. Distinct from guardian emergency halt.
    bool public gracefullyShutdown;
    bool public latestIssuanceClosed;
    bytes32 public latestBlock;
    bytes32 public latestStateRoot;
    /// @notice Commitment to the bounded consensus continuation context at
    /// `latestHeight`: the MTP ancestry and RandomX seed anchors needed by the
    /// next proof. The immutable verifier defines and checks its canonical form.
    bytes32 public latestContextHash;
    uint256 public latestTotalDifficulty;
    uint128 public latestTotalIssued;
    uint128 public latestTotalBurned;
    uint128 public previousTotalIssued;
    uint128 public previousTotalBurned;

    struct PendingCandidate {
        bytes32 statementHash;
        uint64 height;
        uint64 readyAt;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 contextHash;
        uint256 totalDifficulty;
        uint128 totalIssued;
        uint128 totalBurned;
        uint64 confirmationHeight;
        bytes32 confirmationBlock;
        uint256 confirmationTotalDifficulty;
        uint64 confirmationTimestamp;
    }

    PendingCandidate public candidate;
    bool public candidateIssuanceClosed;

    struct Config {
        bytes32 bridgeDomain;
        uint32 domNetworkMagic;
        bytes32 domChainId;
        uint64 firstV4Height;
        bytes32 activationEmptyStateRoot;
        bytes32 activationScheduleCommitment;
        uint32 checkpointInterval;
        uint32 confirmationDepth;
        uint64 challengePeriod;
        IDOMCheckpointVerifier verifier;
        address guardian;
        uint64 initialHeight;
        bytes32 initialBlock;
        bytes32 initialStateRoot;
        bytes32 initialContextHash;
        uint256 initialTotalDifficulty;
    }

    struct CheckpointInput {
        uint64 previousHeight;
        bytes32 previousBlock;
        bytes32 previousStateRoot;
        bytes32 previousContextHash;
        uint256 previousTotalDifficulty;
        uint64 height;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 contextHash;
        uint256 totalDifficulty;
        uint128 totalIssued;
        uint128 totalBurned;
        bool issuanceClosed;
        uint64 confirmationHeight;
        bytes32 confirmationBlock;
        uint256 confirmationTotalDifficulty;
        uint64 confirmationTimestamp;
    }

    event Checkpoint(
        bytes32 indexed bridgeDomain,
        uint32 indexed domNetworkMagic,
        uint64 domHeight,
        bytes32 domBlock,
        bytes32 domStateRoot,
        bytes32 checkpointConfigHash
    );
    /// @notice The ratified predecessor anchor is deliberately a different
    /// event from proof-authorized checkpoints. A burn witness can therefore
    /// never treat constructor output itself as a proved consensus extension.
    event CheckpointBootstrap(
        bytes32 indexed bridgeDomain,
        uint32 indexed domNetworkMagic,
        uint64 domHeight,
        bytes32 domBlock,
        bytes32 domStateRoot,
        bytes32 checkpointConfigHash
    );
    event CheckpointCandidate(
        bytes32 indexed bridgeDomain,
        uint32 indexed domNetworkMagic,
        uint64 domHeight,
        bytes32 domBlock,
        bytes32 domStateRoot,
        bytes32 domContextHash,
        uint256 domTotalDifficulty,
        uint64 confirmationHeight,
        bytes32 confirmationBlock,
        uint256 confirmationTotalDifficulty,
        uint64 confirmationTimestamp,
        uint64 readyAt,
        bytes32 statementHash
    );
    event CheckpointCandidateEconomics(
        bytes32 indexed statementHash, uint128 totalIssued, uint128 totalBurned, bool issuanceClosed
    );
    event CheckpointFinalizedV2(
        bytes32 indexed statementHash,
        bytes32 domContextHash,
        uint256 domTotalDifficulty,
        uint128 totalIssued,
        uint128 totalBurned,
        bool issuanceClosed,
        uint256 checkpointCount
    );
    event PermanentlyHalted(address indexed guardian);
    event GracefullyShutdown(uint64 indexed domHeight, bytes32 indexed domBlock, uint128 terminalSupply);

    error InvalidConfiguration();
    error ProductionUnavailable();
    error InvalidCheckpoint();
    error InvalidProof();
    error CandidateNotBetter();
    error CandidateWindowClosed();
    error NoCandidate();
    error TooEarly();
    error VerifierChanged();
    error GuardianChanged();
    error Unauthorized();
    error IsHalted();
    error NotGracefullyClosable();

    constructor(Config memory config) {
        address verifierAddress = address(config.verifier);
        bytes32 codeHash = verifierAddress.codehash;
        bytes32 guardianHash = config.guardian.codehash;
        if (
            config.bridgeDomain == bytes32(0) || config.domNetworkMagic == 0 || config.domChainId == bytes32(0)
                || config.firstV4Height == 0 || config.activationEmptyStateRoot == bytes32(0)
                || config.activationScheduleCommitment == bytes32(0) || verifierAddress.code.length == 0
                || config.checkpointInterval == 0 || config.checkpointInterval > MAX_CHECKPOINT_INTERVAL
                || config.confirmationDepth == 0 || config.confirmationDepth > config.checkpointInterval
                || config.challengePeriod < MIN_CHALLENGE_PERIOD || config.challengePeriod > MAX_CHALLENGE_PERIOD
                || codeHash == bytes32(0) || config.guardian.code.length == 0 || guardianHash == bytes32(0)
                || config.guardian == verifierAddress || config.initialHeight == 0 || config.initialBlock == bytes32(0)
                || config.initialStateRoot != config.activationEmptyStateRoot || config.initialContextHash == bytes32(0)
                || config.initialTotalDifficulty == 0 || config.initialHeight == type(uint64).max
                || config.initialHeight + 1 != config.firstV4Height
                || uint256(config.initialHeight) + config.checkpointInterval + config.confirmationDepth
                    > type(uint64).max
        ) revert InvalidConfiguration();

        bytes32 verifierConfiguration = _readVerifierConfig(config.verifier);
        if (verifierConfiguration == bytes32(0) || _readVerifierCapability(verifierAddress) != PROOF_ACCEPTED) {
            revert InvalidConfiguration();
        }
        (address guardianImpl, bytes32 guardianImplHash, bytes32 guardianOwners) =
            _controlPlaneIdentity(config.guardian);
        bytes32 guardianIdentityHash =
            _controlPlaneIdentityHash(config.guardian, guardianHash, guardianImpl, guardianImplHash, guardianOwners);
        bytes32 registryConfiguration =
            _checkpointConfigHash(config, codeHash, verifierConfiguration, guardianIdentityHash);
        if (
            block.chainid == 1
                && (PRODUCTION_VERIFIER_CODE_HASH == bytes32(0)
                    || PRODUCTION_VERIFIER_CONFIG_HASH == bytes32(0)
                    || PRODUCTION_CHECKPOINT_CONFIG_HASH == bytes32(0)
                    || codeHash != PRODUCTION_VERIFIER_CODE_HASH
                    || verifierConfiguration != PRODUCTION_VERIFIER_CONFIG_HASH
                    || registryConfiguration != PRODUCTION_CHECKPOINT_CONFIG_HASH)
        ) revert ProductionUnavailable();

        bridgeDomain = config.bridgeDomain;
        domNetworkMagic = config.domNetworkMagic;
        domChainId = config.domChainId;
        firstV4Height = config.firstV4Height;
        activationEmptyStateRoot = config.activationEmptyStateRoot;
        activationScheduleCommitment = config.activationScheduleCommitment;
        checkpointInterval = config.checkpointInterval;
        confirmationDepth = config.confirmationDepth;
        challengePeriod = config.challengePeriod;
        verifier = config.verifier;
        verifierCodeHash = codeHash;
        verifierConfigHash = verifierConfiguration;
        guardian = config.guardian;
        guardianCodeHash = guardianHash;
        guardianImplementation = guardianImpl;
        guardianImplementationCodeHash = guardianImplHash;
        guardianOwnersCommitment = guardianOwners;
        checkpointConfigHash = registryConfiguration;
        latestHeight = config.initialHeight;
        latestBlock = config.initialBlock;
        latestStateRoot = config.initialStateRoot;
        latestContextHash = config.initialContextHash;
        latestTotalDifficulty = config.initialTotalDifficulty;
        checkpointCount = 1;

        // Constructor static calls execute before runtime code exists; any
        // failed identity check reverts this bootstrap event.
        // forge-lint: disable-next-item(reentrancy-events)
        emit CheckpointBootstrap(
            config.bridgeDomain,
            config.domNetworkMagic,
            config.initialHeight,
            config.initialBlock,
            config.initialStateRoot,
            registryConfiguration
        );
    }

    /// @notice Hash the exact public statement consumed by the immutable verifier.
    function checkpointStatementHash(CheckpointInput calldata checkpoint) public view returns (bytes32) {
        bytes memory prefix = abi.encode(
            CHECKPOINT_STATEMENT_TYPEHASH,
            bridgeDomain,
            domNetworkMagic,
            NATIVE_STATE_VERSION,
            TRANSITION_BATCH_VERSION,
            checkpoint.previousHeight,
            checkpoint.previousBlock,
            checkpoint.previousStateRoot,
            checkpoint.previousContextHash,
            checkpoint.previousTotalDifficulty,
            checkpoint.height,
            checkpoint.blockHash
        );
        return keccak256(
            bytes.concat(
                prefix,
                abi.encode(
                    checkpoint.stateRoot,
                    checkpoint.contextHash,
                    checkpoint.totalDifficulty,
                    checkpoint.totalIssued,
                    checkpoint.totalBurned,
                    checkpoint.issuanceClosed,
                    checkpoint.confirmationHeight,
                    checkpoint.confirmationBlock,
                    checkpoint.confirmationTotalDifficulty,
                    checkpoint.confirmationTimestamp,
                    block.chainid,
                    address(this),
                    activationScheduleCommitment,
                    checkpointConfigHash
                )
            )
        );
    }

    /// @notice Reports the exact fail-closed guardian predicate used by the
    /// irreversible halt path, including Safe policy when applicable.
    function guardianControlHealthy() external view returns (bool) {
        return _controlPlaneUnchanged(
            guardian, guardianCodeHash, guardianImplementation, guardianImplementationCodeHash, guardianOwnersCommitment
        );
    }

    /// @notice Submit or improve the work-leading candidate for the next fixed round.
    /// Only finalization emits the Checkpoint event consumed by burn witnesses.
    function submitCheckpointCandidate(CheckpointInput calldata checkpoint, bytes calldata proof) external {
        if (halted) revert IsHalted();
        uint256 expectedHeight = uint256(latestHeight) + checkpointInterval;
        uint256 expectedConfirmationHeight = expectedHeight + confirmationDepth;
        if (
            checkpoint.previousHeight != latestHeight || checkpoint.previousBlock != latestBlock
                || checkpoint.previousStateRoot != latestStateRoot
                || checkpoint.previousContextHash != latestContextHash
                || checkpoint.previousTotalDifficulty != latestTotalDifficulty
                || expectedConfirmationHeight > type(uint64).max || uint256(checkpoint.height) != expectedHeight
                || checkpoint.blockHash == bytes32(0) || checkpoint.stateRoot == bytes32(0)
                || checkpoint.contextHash == bytes32(0) || checkpoint.contextHash == checkpoint.previousContextHash
                || checkpoint.totalDifficulty <= checkpoint.previousTotalDifficulty
                || checkpoint.totalIssued < latestTotalIssued || checkpoint.totalBurned < latestTotalBurned
                || (latestIssuanceClosed && !checkpoint.issuanceClosed)
                // Once a finalized checkpoint closes issuance, later proofs may
                // advance burns but can never create another unit. Enforce this
                // economic latch here as well as inside the native proof program.
                || (latestIssuanceClosed && checkpoint.totalIssued != latestTotalIssued)
                || checkpoint.totalBurned > checkpoint.totalIssued
                || uint256(checkpoint.confirmationHeight) != expectedConfirmationHeight
                || checkpoint.confirmationBlock == bytes32(0) || checkpoint.confirmationBlock == checkpoint.blockHash
                || checkpoint.confirmationTotalDifficulty <= checkpoint.totalDifficulty
                || checkpoint.confirmationTimestamp == 0
                // A proved suffix may be old, but can never end in Ethereum's future.
                // forge-lint: disable-next-line(block-timestamp)
                || checkpoint.confirmationTimestamp > block.timestamp
                || checkpoint.blockHash == checkpoint.previousBlock || proof.length != EVM_PROOF_BYTES
                || bytes4(proof[:4]) != RISC_ZERO_GROTH16_V3_SELECTOR
        ) {
            revert InvalidCheckpoint();
        }
        // Reject terminal input errors before probing the external Safe and
        // verifier identities. Those calls are bounded, but need not be paid
        // for by a permissionless relayer whose calldata is already invalid.
        _requireGuardianUnchanged();
        _requireVerifierUnchanged();
        bytes32 statementHash = checkpointStatementHash(checkpoint);
        // Candidate rank and the immutable window are local state. Reject a
        // closed or non-improving submission before spending up to five million
        // gas in the proof adapter. Selection repeats this fail-closed check.
        _requireCandidateAdmissible(checkpoint, statementHash);
        (bool ok, bytes32 result) = _staticcallWord(
            address(verifier),
            VERIFIER_GAS_LIMIT,
            abi.encodeCall(IDOMCheckpointVerifier.verifyDOMCheckpoint, (statementHash, proof))
        );
        if (!ok || result != PROOF_ACCEPTED) revert InvalidProof();
        _requireVerifierUnchanged();

        _selectCandidate(checkpoint, statementHash);
    }

    function _selectCandidate(CheckpointInput calldata checkpoint, bytes32 statementHash) private {
        _requireCandidateAdmissible(checkpoint, statementHash);
        PendingCandidate memory current = candidate;
        uint64 readyAt = current.statementHash == bytes32(0) ? _timestampAfter(challengePeriod) : current.readyAt;
        candidate = PendingCandidate({
            statementHash: statementHash,
            height: checkpoint.height,
            readyAt: readyAt,
            blockHash: checkpoint.blockHash,
            stateRoot: checkpoint.stateRoot,
            contextHash: checkpoint.contextHash,
            totalDifficulty: checkpoint.totalDifficulty,
            totalIssued: checkpoint.totalIssued,
            totalBurned: checkpoint.totalBurned,
            confirmationHeight: checkpoint.confirmationHeight,
            confirmationBlock: checkpoint.confirmationBlock,
            confirmationTotalDifficulty: checkpoint.confirmationTotalDifficulty,
            confirmationTimestamp: checkpoint.confirmationTimestamp
        });
        candidateIssuanceClosed = checkpoint.issuanceClosed;
        _emitCandidate(checkpoint, readyAt, statementHash);
    }

    function _requireCandidateAdmissible(CheckpointInput calldata checkpoint, bytes32 statementHash) private view {
        PendingCandidate memory current = candidate;
        // Ethereum time is the explicit, immutable challenge-window clock.
        // forge-lint: disable-next-line(block-timestamp)
        if (current.statementHash != bytes32(0) && block.timestamp >= current.readyAt) {
            revert CandidateWindowClosed();
        }
        if (current.statementHash != bytes32(0) && !_candidateIsBetter(checkpoint, statementHash, current)) {
            revert CandidateNotBetter();
        }
    }

    /// @dev Strict total order: most confirmed work wins; exact work ties use
    /// the smaller confirmation block, then the smaller statement hash. The
    /// final key removes relayer/mempool arrival order from exact-rank ties.
    function _candidateIsBetter(
        CheckpointInput calldata checkpoint,
        bytes32 statementHash,
        PendingCandidate memory current
    ) private pure returns (bool) {
        if (checkpoint.confirmationTotalDifficulty != current.confirmationTotalDifficulty) {
            return checkpoint.confirmationTotalDifficulty > current.confirmationTotalDifficulty;
        }
        if (checkpoint.confirmationBlock != current.confirmationBlock) {
            return uint256(checkpoint.confirmationBlock) < uint256(current.confirmationBlock);
        }
        return uint256(statementHash) < uint256(current.statementHash);
    }

    function _emitCandidate(CheckpointInput calldata checkpoint, uint64 readyAt, bytes32 statementHash) private {
        // The only preceding external interaction is STATICCALL with a
        // bounded return word, so it cannot mutate or reenter state changes.
        // forge-lint: disable-next-item(reentrancy-events)
        emit CheckpointCandidate(
            bridgeDomain,
            domNetworkMagic,
            checkpoint.height,
            checkpoint.blockHash,
            checkpoint.stateRoot,
            checkpoint.contextHash,
            checkpoint.totalDifficulty,
            checkpoint.confirmationHeight,
            checkpoint.confirmationBlock,
            checkpoint.confirmationTotalDifficulty,
            checkpoint.confirmationTimestamp,
            readyAt,
            statementHash
        );
        emit CheckpointCandidateEconomics(
            statementHash, checkpoint.totalIssued, checkpoint.totalBurned, checkpoint.issuanceClosed
        );
    }

    /// @notice Finalize the best proved candidate after the non-resetting challenge window.
    function finalizeCheckpoint() external {
        if (halted) revert IsHalted();
        _requireGuardianUnchanged();
        PendingCandidate memory current = candidate;
        if (current.statementHash == bytes32(0)) revert NoCandidate();
        // Ethereum time is the explicit, immutable challenge-window clock.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < current.readyAt) revert TooEarly();
        _requireVerifierUnchanged();
        latestHeight = current.height;
        latestBlock = current.blockHash;
        latestStateRoot = current.stateRoot;
        latestContextHash = current.contextHash;
        latestTotalDifficulty = current.totalDifficulty;
        previousTotalIssued = latestTotalIssued;
        previousTotalBurned = latestTotalBurned;
        latestTotalIssued = current.totalIssued;
        latestTotalBurned = current.totalBurned;
        latestIssuanceClosed = candidateIssuanceClosed;
        ++checkpointCount;
        delete candidate;
        delete candidateIssuanceClosed;
        // Verifier identity was checked by STATICCALL before effects; static
        // context prevents state-mutating callback paths.
        // forge-lint: disable-next-item(reentrancy-events)
        emit Checkpoint(
            bridgeDomain, domNetworkMagic, current.height, current.blockHash, current.stateRoot, checkpointConfigHash
        );
        emit CheckpointFinalizedV2(
            current.statementHash,
            current.contextHash,
            current.totalDifficulty,
            current.totalIssued,
            current.totalBurned,
            latestIssuanceClosed,
            checkpointCount
        );
    }

    /// @notice Permissionlessly enter the proof-authorized terminal state only
    /// after native issuance is closed and every issued unit has been burned.
    /// This is deliberately distinct from the guardian emergency halt.
    function finalizeGracefulShutdown() external {
        if (halted) revert IsHalted();
        if (!latestIssuanceClosed || latestTotalBurned != latestTotalIssued) revert NotGracefullyClosable();
        _requireGuardianUnchanged();
        _requireVerifierUnchanged();
        halted = true;
        gracefullyShutdown = true;
        delete candidate;
        delete candidateIssuanceClosed;
        // Guardian and verifier identity probes above are bounded STATICCALLs;
        // static context cannot mutate or reenter before this terminal event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit GracefullyShutdown(latestHeight, latestBlock, latestTotalIssued);
    }

    /// @notice Irreversibly stop new checkpoints as an emergency action. Existing events remain valid.
    function haltPermanently() external {
        if (msg.sender != guardian) revert Unauthorized();
        _requireGuardianUnchanged();
        if (halted) revert IsHalted();
        halted = true;
        // The preceding identity probe is STATICCALL-only and cannot reenter
        // with state changes or fabricate a successful halt event.
        // forge-lint: disable-next-item(reentrancy-events)
        emit PermanentlyHalted(msg.sender);
    }

    function _checkpointConfigHash(
        Config memory config,
        bytes32 codeHash,
        bytes32 verifierConfiguration,
        bytes32 guardianIdentityHash
    ) private view returns (bytes32) {
        bytes memory identityPrefix = abi.encode(
            CHECKPOINT_IDENTITY_TYPEHASH,
            block.chainid,
            address(this),
            config.bridgeDomain,
            config.domNetworkMagic,
            config.domChainId,
            config.firstV4Height
        );
        bytes32 identityHash = keccak256(
            bytes.concat(
                identityPrefix,
                abi.encode(
                    config.checkpointInterval,
                    config.confirmationDepth,
                    config.challengePeriod,
                    address(config.verifier),
                    codeHash,
                    verifierConfiguration
                )
            )
        );
        bytes32 bootstrapHash = keccak256(
            abi.encode(
                CHECKPOINT_BOOTSTRAP_TYPEHASH,
                guardianIdentityHash,
                config.initialHeight,
                config.initialBlock,
                config.initialContextHash,
                config.initialTotalDifficulty
            )
        );
        return keccak256(abi.encode(CHECKPOINT_CONFIG_TYPEHASH, identityHash, bootstrapHash));
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

    function _safeOwnersIntact(address account) private view returns (bool intact) {
        (intact,) = _safeOwnersIdentity(account);
    }

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

    function _safeGuardEmpty(address account) private view returns (bool empty) {
        bytes memory callData =
            abi.encodeWithSelector(SAFE_GET_STORAGE_AT_SELECTOR, SAFE_GUARD_STORAGE_SLOT, uint256(1));
        bytes32 offset;
        bytes32 length;
        bytes32 guard;
        uint256 returnSize;
        assembly ("memory-safe") {
            let output := mload(0x40)
            empty := staticcall(CONTROL_PLANE_GAS_LIMIT, account, add(callData, 32), mload(callData), output, 96)
            returnSize := returndatasize()
            offset := mload(output)
            length := mload(add(output, 32))
            guard := mload(add(output, 64))
        }
        empty = empty && returnSize == 96 && uint256(offset) == 32 && uint256(length) == 32 && guard == bytes32(0);
    }

    function _safeFallbackHandlerIntact(address account) private view returns (bool intact) {
        bytes memory callData =
            abi.encodeWithSelector(SAFE_GET_STORAGE_AT_SELECTOR, SAFE_FALLBACK_HANDLER_STORAGE_SLOT, uint256(1));
        bytes32 offset;
        bytes32 length;
        bytes32 handler;
        uint256 returnSize;
        assembly ("memory-safe") {
            let output := mload(0x40)
            intact := staticcall(CONTROL_PLANE_GAS_LIMIT, account, add(callData, 32), mload(callData), output, 96)
            returnSize := returndatasize()
            offset := mload(output)
            length := mload(add(output, 32))
            handler := mload(add(output, 64))
        }
        intact = intact && returnSize == 96 && uint256(offset) == 32 && uint256(length) == 32
            && uint256(handler) <= type(uint160).max
            && address(uint160(uint256(handler))) == SAFE_MAINNET_FALLBACK_HANDLER
            && SAFE_MAINNET_FALLBACK_HANDLER.codehash == SAFE_MAINNET_FALLBACK_HANDLER_CODE_HASH;
    }

    function _requireVerifierUnchanged() private view {
        if (
            address(verifier).codehash != verifierCodeHash || _readVerifierConfig(verifier) != verifierConfigHash
                || _readVerifierCapability(address(verifier)) != PROOF_ACCEPTED
        ) {
            revert VerifierChanged();
        }
    }

    /// @dev Checkpoint progression must stop when its emergency authority no
    /// longer matches the immutable deployment policy. Otherwise a modified
    /// Safe could leave proof submission live while making the irreversible
    /// halt path unavailable.
    function _requireGuardianUnchanged() private view {
        if (!_controlPlaneUnchanged(
                guardian,
                guardianCodeHash,
                guardianImplementation,
                guardianImplementationCodeHash,
                guardianOwnersCommitment
            )) {
            revert GuardianChanged();
        }
    }

    function _readVerifierConfig(IDOMCheckpointVerifier verifier_) private view returns (bytes32 value) {
        (bool ok, bytes32 result) =
            _staticcallWord(address(verifier_), VERIFIER_GAS_LIMIT, abi.encodeCall(verifier_.verifierConfigHash, ()));
        if (!ok) return bytes32(0);
        value = result;
    }

    /// @dev A checkpoint deployment must not accept the finalized-burn adapter
    /// merely because it also exposes a nonzero immutable configuration hash.
    function _readVerifierCapability(address verifierAddress) private view returns (bytes32 value) {
        (bool ok, bytes32 result) =
            _staticcallWord(verifierAddress, VERIFIER_GAS_LIMIT, abi.encodeWithSignature("PROOF_ACCEPTED()"));
        if (ok) value = result;
    }

    /// @dev Copies exactly one return word. An untrusted verifier cannot force
    /// Solidity to allocate or copy attacker-selected return-data length.
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

    function _checkedTimestamp(uint256 value) private pure returns (uint64) {
        if (value > type(uint64).max) revert InvalidCheckpoint();
        // The preceding bound proves that narrowing preserves the value.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(value);
    }

    function _timestampAfter(uint256 delay) private view returns (uint64) {
        if (delay > type(uint64).max || block.timestamp > type(uint64).max - delay) revert InvalidCheckpoint();
        return _checkedTimestamp(block.timestamp + delay);
    }
}
