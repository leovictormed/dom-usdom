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
    uint256 public constant MAX_PROOF_BYTES = 64 * 1024;
    uint256 public constant VERIFIER_GAS_LIMIT = 5_000_000;
    uint256 public constant MAX_CHECKPOINT_INTERVAL = 360;
    uint256 public constant MIN_CHALLENGE_PERIOD = 1 days;
    uint256 public constant MAX_CHALLENGE_PERIOD = 30 days;
    bytes32 public constant PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V2");
    uint16 public constant NATIVE_STATE_VERSION = 2;
    uint16 public constant TRANSITION_BATCH_VERSION = 3;
    bytes32 public constant LEGACY_CHECKPOINT_STATEMENT_TYPEHASH = keccak256(
        "DOMCheckpoint(bytes32 bridgeDomain,uint32 domNetworkMagic,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)"
    );
    bytes32 public constant CHECKPOINT_STATEMENT_TYPEHASH = keccak256(
        "DOMCheckpointV2(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)"
    );
    bytes32 public constant CHECKPOINT_IDENTITY_TYPEHASH = keccak256(
        "DOMCheckpointIdentity(uint256 ethereumChainId,address registry,bytes32 bridgeDomain,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,bytes32 activationEmptyStateRoot,bytes32 activationScheduleCommitment,uint32 checkpointInterval,uint32 confirmationDepth,uint64 challengePeriod,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash)"
    );
    bytes32 public constant CHECKPOINT_BOOTSTRAP_TYPEHASH = keccak256(
        "DOMCheckpointBootstrap(address guardian,bytes32 guardianCodeHash,uint64 initialHeight,bytes32 initialBlock,bytes32 initialStateRoot,bytes32 initialContextHash,uint256 initialTotalDifficulty)"
    );
    bytes32 public constant CHECKPOINT_CONFIG_TYPEHASH =
        keccak256("DOMCheckpointConfig(bytes32 identityHash,bytes32 bootstrapHash)");

    // A production release must pin all three values from independently built
    // and ratified artifacts. Zeros make chain ID 1 deployment fail closed.
    bytes32 public constant PRODUCTION_VERIFIER_CODE_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_VERIFIER_CONFIG_HASH = bytes32(0);
    bytes32 public constant PRODUCTION_CHECKPOINT_CONFIG_HASH = bytes32(0);

    bytes32 public immutable bridgeDomain;
    uint32 public immutable domNetworkMagic;
    bytes32 public immutable domChainId;
    uint64 public immutable firstV4Height;
    bytes32 public immutable activationEmptyStateRoot;
    bytes32 public immutable activationScheduleCommitment;
    uint32 public immutable checkpointInterval;
    uint32 public immutable confirmationDepth;
    uint64 public immutable challengePeriod;
    IDOMCheckpointVerifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable verifierConfigHash;
    address public immutable guardian;
    bytes32 public immutable guardianCodeHash;

    // Deliberately the first storage variable. Ethereum witnesses authenticate
    // slot zero and the Rust policy additionally pins this contract's code hash.
    bytes32 public checkpointConfigHash;
    uint64 public latestHeight;
    uint64 public checkpointCount;
    bool public halted;
    bytes32 public latestBlock;
    bytes32 public latestStateRoot;
    /// @notice Commitment to the bounded consensus continuation context at
    /// `latestHeight`: the MTP ancestry and RandomX seed anchors needed by the
    /// next proof. The immutable verifier defines and checks its canonical form.
    bytes32 public latestContextHash;
    uint256 public latestTotalDifficulty;

    struct PendingCandidate {
        bytes32 statementHash;
        uint64 height;
        uint64 readyAt;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 contextHash;
        uint256 totalDifficulty;
        uint64 confirmationHeight;
        bytes32 confirmationBlock;
        uint256 confirmationTotalDifficulty;
        uint64 confirmationTimestamp;
    }

    PendingCandidate public candidate;

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
    event PermanentlyHalted(address indexed guardian);

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
        if (verifierConfiguration == bytes32(0)) revert InvalidConfiguration();
        bytes32 registryConfiguration = _checkpointConfigHash(config, codeHash, verifierConfiguration, guardianHash);
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
                || uint256(checkpoint.confirmationHeight) != expectedConfirmationHeight
                || checkpoint.confirmationBlock == bytes32(0) || checkpoint.confirmationBlock == checkpoint.blockHash
                || checkpoint.confirmationTotalDifficulty <= checkpoint.totalDifficulty
                || checkpoint.confirmationTimestamp == 0
                // A proved suffix may be old, but can never end in Ethereum's future.
                // forge-lint: disable-next-line(block-timestamp)
                || checkpoint.confirmationTimestamp > block.timestamp
                || checkpoint.blockHash == checkpoint.previousBlock || proof.length == 0
                || proof.length > MAX_PROOF_BYTES
        ) {
            revert InvalidCheckpoint();
        }
        _requireVerifierUnchanged();
        bytes32 statementHash = checkpointStatementHash(checkpoint);
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
        PendingCandidate memory current = candidate;
        // Ethereum time is the explicit, immutable challenge-window clock.
        // forge-lint: disable-next-line(block-timestamp)
        if (current.statementHash != bytes32(0) && block.timestamp >= current.readyAt) {
            revert CandidateWindowClosed();
        }
        if (
            current.statementHash != bytes32(0)
                && (checkpoint.confirmationTotalDifficulty < current.confirmationTotalDifficulty
                    || (checkpoint.confirmationTotalDifficulty == current.confirmationTotalDifficulty
                        && uint256(checkpoint.confirmationBlock) >= uint256(current.confirmationBlock)))
        ) revert CandidateNotBetter();
        uint64 readyAt = current.statementHash == bytes32(0)
            ? _checkedTimestamp(block.timestamp + challengePeriod)
            : current.readyAt;
        candidate = PendingCandidate({
            statementHash: statementHash,
            height: checkpoint.height,
            readyAt: readyAt,
            blockHash: checkpoint.blockHash,
            stateRoot: checkpoint.stateRoot,
            contextHash: checkpoint.contextHash,
            totalDifficulty: checkpoint.totalDifficulty,
            confirmationHeight: checkpoint.confirmationHeight,
            confirmationBlock: checkpoint.confirmationBlock,
            confirmationTotalDifficulty: checkpoint.confirmationTotalDifficulty,
            confirmationTimestamp: checkpoint.confirmationTimestamp
        });
        _emitCandidate(checkpoint, readyAt, statementHash);
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
    }

    /// @notice Finalize the best proved candidate after the non-resetting challenge window.
    function finalizeCheckpoint() external {
        if (halted) revert IsHalted();
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
        ++checkpointCount;
        delete candidate;
        // Verifier identity was checked by STATICCALL before effects; static
        // context prevents state-mutating callback paths.
        // forge-lint: disable-next-item(reentrancy-events)
        emit Checkpoint(
            bridgeDomain, domNetworkMagic, current.height, current.blockHash, current.stateRoot, checkpointConfigHash
        );
    }

    /// @notice Irreversibly stop new checkpoints. Existing events remain valid.
    function haltPermanently() external {
        if (msg.sender != guardian) revert Unauthorized();
        if (guardian.codehash != guardianCodeHash) revert GuardianChanged();
        if (halted) revert IsHalted();
        halted = true;
        emit PermanentlyHalted(msg.sender);
    }

    function _checkpointConfigHash(
        Config memory config,
        bytes32 codeHash,
        bytes32 verifierConfiguration,
        bytes32 guardianHash
    ) private view returns (bytes32) {
        bytes memory identityPrefix = abi.encode(
            CHECKPOINT_IDENTITY_TYPEHASH,
            block.chainid,
            address(this),
            config.bridgeDomain,
            config.domNetworkMagic,
            config.domChainId,
            config.firstV4Height,
            config.activationEmptyStateRoot,
            config.activationScheduleCommitment
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
                config.guardian,
                guardianHash,
                config.initialHeight,
                config.initialBlock,
                config.initialStateRoot,
                config.initialContextHash,
                config.initialTotalDifficulty
            )
        );
        return keccak256(abi.encode(CHECKPOINT_CONFIG_TYPEHASH, identityHash, bootstrapHash));
    }

    function _requireVerifierUnchanged() private view {
        if (address(verifier).codehash != verifierCodeHash || _readVerifierConfig(verifier) != verifierConfigHash) {
            revert VerifierChanged();
        }
    }

    function _readVerifierConfig(IDOMCheckpointVerifier verifier_) private view returns (bytes32 value) {
        (bool ok, bytes32 result) =
            _staticcallWord(address(verifier_), VERIFIER_GAS_LIMIT, abi.encodeCall(verifier_.verifierConfigHash, ()));
        if (!ok) return bytes32(0);
        value = result;
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
}
