// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {DOMCheckpointRegistry, IDOMCheckpointVerifier} from "../../contracts/DOMCheckpointRegistry.sol";
import {MockGovernance, MockMutableSingletonControl} from "./Mocks.sol";
import {TestBase, Vm} from "./TestBase.sol";

contract MockDOMCheckpointVerifier is IDOMCheckpointVerifier {
    bytes32 public PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V3");
    bytes32 public override verifierConfigHash = keccak256("DOM checkpoint verifier test configuration");
    mapping(bytes32 => bool) private accepted;

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function setConfigHash(bytes32 value) external {
        verifierConfigHash = value;
    }

    function setCapability(bytes32 value) external {
        PROOF_ACCEPTED = value;
    }

    function verifyDOMCheckpoint(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
        return accepted[keccak256(abi.encode(statementHash, proof))] ? keccak256("DOM_CHECKPOINT_PROOF_V3") : bytes32(0);
    }
}

contract HostileDOMCheckpointVerifier is IDOMCheckpointVerifier {
    bytes32 public constant PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V3");
    enum Mode {
        Reject,
        Accept,
        RevertCall,
        ShortReturn,
        TrailingByteReturn,
        OversizedReturn,
        ReturnBomb
    }
    bytes32 public override verifierConfigHash = keccak256("hostile checkpoint verifier configuration");
    Mode public mode;

    function setMode(Mode value) external {
        mode = value;
    }

    function verifyDOMCheckpoint(bytes32, bytes calldata) external view returns (bytes32) {
        if (mode == Mode.RevertCall) revert("hostile verifier");
        if (mode == Mode.ShortReturn) {
            bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V3");
            assembly ("memory-safe") {
                mstore(0, accepted)
                return(0, 31)
            }
        }
        if (mode == Mode.TrailingByteReturn) {
            bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V3");
            assembly ("memory-safe") {
                mstore(0, accepted)
                mstore8(32, 0)
                return(0, 33)
            }
        }
        if (mode == Mode.OversizedReturn) {
            bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V3");
            assembly ("memory-safe") {
                mstore(0, accepted)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (mode == Mode.ReturnBomb) {
            bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V3");
            assembly ("memory-safe") {
                mstore(0, accepted)
                return(0, 0x100000)
            }
        }
        return mode == Mode.Accept ? keccak256("DOM_CHECKPOINT_PROOF_V3") : bytes32(0);
    }
}

contract ReturnBombConfigDOMCheckpointVerifier is IDOMCheckpointVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        bytes32 configured = keccak256("return-bomb checkpoint verifier configuration");
        assembly ("memory-safe") {
            mstore(0, configured)
            return(0, 0x100000)
        }
    }

    function verifyDOMCheckpoint(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("DOM_CHECKPOINT_PROOF_V3");
    }
}

contract ZeroConfigDOMCheckpointVerifier is IDOMCheckpointVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        return bytes32(0);
    }

    function verifyDOMCheckpoint(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("DOM_CHECKPOINT_PROOF_V3");
    }
}

contract BurnCapabilityOnCheckpointInterface is IDOMCheckpointVerifier {
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 public constant override verifierConfigHash = keccak256("wrong finalized-burn capability");

    function verifyDOMCheckpoint(bytes32, bytes calldata) external pure returns (bytes32) {
        return PROOF_ACCEPTED;
    }
}

contract MalformedCheckpointCapabilityVerifier is IDOMCheckpointVerifier {
    bytes32 public constant override verifierConfigHash = keccak256("malformed checkpoint capability config");

    function verifyDOMCheckpoint(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("DOM_CHECKPOINT_PROOF_V3");
    }

    fallback() external {
        bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V3");
        assembly ("memory-safe") {
            mstore(0, accepted)
            return(0, 0x100000)
        }
    }
}

contract DOMCheckpointRegistryTest is TestBase {
    bytes32 constant DOMAIN = keccak256("DOM checkpoint registry bridge domain");
    bytes32 constant DOM_CHAIN_ID = keccak256("DOM checkpoint registry chain ID");
    bytes32 constant ACTIVATION = keccak256("DOM checkpoint registry activation schedule");
    bytes32 constant INITIAL_BLOCK = keccak256("DOM checkpoint initial block");
    bytes32 constant INITIAL_STATE = keccak256("DOM checkpoint initial state");
    bytes32 constant INITIAL_CONTEXT = keccak256("DOM checkpoint initial consensus context");
    uint32 constant NETWORK_MAGIC = 0xA1B2C3D4;
    uint64 constant INITIAL_HEIGHT = 100_000;
    uint64 constant FIRST_V4_HEIGHT = INITIAL_HEIGHT + 1;
    uint32 constant INTERVAL = 360;
    uint32 constant CONFIRMATION_DEPTH = 30;
    uint64 constant CHALLENGE_PERIOD = 2 days;
    uint256 constant INITIAL_TOTAL_DIFFICULTY = 1_000_000;

    MockDOMCheckpointVerifier checkpointVerifier;
    MockGovernance guardian;
    DOMCheckpointRegistry registry;
    MockMutableSingletonControl scratchSafeGuardian;
    DOMCheckpointRegistry scratchProtectedRegistry;

    function setUp() public {
        checkpointVerifier = new MockDOMCheckpointVerifier();
        guardian = new MockGovernance();
        registry = new DOMCheckpointRegistry(config(checkpointVerifier));
    }

    function config(IDOMCheckpointVerifier verifier_) internal view returns (DOMCheckpointRegistry.Config memory) {
        return DOMCheckpointRegistry.Config({
            bridgeDomain: DOMAIN,
            domNetworkMagic: NETWORK_MAGIC,
            domChainId: DOM_CHAIN_ID,
            firstV4Height: FIRST_V4_HEIGHT,
            activationEmptyStateRoot: INITIAL_STATE,
            activationScheduleCommitment: ACTIVATION,
            checkpointInterval: INTERVAL,
            confirmationDepth: CONFIRMATION_DEPTH,
            challengePeriod: CHALLENGE_PERIOD,
            verifier: verifier_,
            guardian: address(guardian),
            initialHeight: INITIAL_HEIGHT,
            initialBlock: INITIAL_BLOCK,
            initialStateRoot: INITIAL_STATE,
            initialContextHash: INITIAL_CONTEXT,
            initialTotalDifficulty: INITIAL_TOTAL_DIFFICULTY
        });
    }

    function nextCheckpoint() internal pure returns (DOMCheckpointRegistry.CheckpointInput memory) {
        return DOMCheckpointRegistry.CheckpointInput({
            previousHeight: INITIAL_HEIGHT,
            previousBlock: INITIAL_BLOCK,
            previousStateRoot: INITIAL_STATE,
            previousContextHash: INITIAL_CONTEXT,
            previousTotalDifficulty: INITIAL_TOTAL_DIFFICULTY,
            height: INITIAL_HEIGHT + INTERVAL,
            blockHash: keccak256("DOM checkpoint next block"),
            stateRoot: keccak256("DOM checkpoint next state"),
            contextHash: keccak256("DOM checkpoint next consensus context"),
            totalDifficulty: INITIAL_TOTAL_DIFFICULTY + INTERVAL,
            totalIssued: 0,
            totalBurned: 0,
            issuanceClosed: false,
            confirmationHeight: INITIAL_HEIGHT + INTERVAL + CONFIRMATION_DEPTH,
            confirmationBlock: keccak256("DOM checkpoint confirmation block"),
            confirmationTotalDifficulty: INITIAL_TOTAL_DIFFICULTY + INTERVAL + CONFIRMATION_DEPTH,
            confirmationTimestamp: 1
        });
    }

    function markerProof(uint8 marker) internal pure returns (bytes memory) {
        return canonicalRiscZeroProof(bytes32(uint256(marker)));
    }

    function approveAndSubmit(DOMCheckpointRegistry.CheckpointInput memory checkpoint, bytes memory proof) internal {
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        registry.submitCheckpointCandidate(checkpoint, proof);
    }

    function testConstructorCommitsExactConfigurationAtSlotZero() public view {
        bytes memory identityPrefix = abi.encode(
            registry.CHECKPOINT_IDENTITY_TYPEHASH(),
            block.chainid,
            address(registry),
            DOMAIN,
            NETWORK_MAGIC,
            DOM_CHAIN_ID,
            FIRST_V4_HEIGHT
        );
        bytes32 identityHash = keccak256(
            bytes.concat(
                identityPrefix,
                abi.encode(
                    INTERVAL,
                    CONFIRMATION_DEPTH,
                    CHALLENGE_PERIOD,
                    address(checkpointVerifier),
                    address(checkpointVerifier).codehash,
                    checkpointVerifier.verifierConfigHash()
                )
            )
        );
        bytes32 bootstrapHash = keccak256(
            abi.encode(
                registry.CHECKPOINT_BOOTSTRAP_TYPEHASH(),
                keccak256(
                    abi.encode(
                        registry.CONTROL_PLANE_IDENTITY_TYPEHASH(),
                        address(guardian),
                        address(guardian).codehash,
                        address(guardian),
                        address(guardian).codehash,
                        bytes32(0)
                    )
                ),
                INITIAL_HEIGHT,
                INITIAL_BLOCK,
                INITIAL_CONTEXT,
                INITIAL_TOTAL_DIFFICULTY
            )
        );
        bytes32 expected = keccak256(abi.encode(registry.CHECKPOINT_CONFIG_TYPEHASH(), identityHash, bootstrapHash));
        assertEq(registry.checkpointConfigHash(), expected);
        assertEq(vm.load(address(registry), bytes32(0)), expected);
        assertEq(registry.activationScheduleCommitment(), ACTIVATION);
        assertEq(vm.load(address(registry), bytes32(uint256(1))), ACTIVATION);
        assertEq(registry.activationEmptyStateRoot(), INITIAL_STATE);
        assertEq(vm.load(address(registry), bytes32(uint256(2))), INITIAL_STATE);
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);
        assertEq(registry.latestBlock(), INITIAL_BLOCK);
        assertEq(registry.latestStateRoot(), INITIAL_STATE);
        assertEq(registry.latestContextHash(), INITIAL_CONTEXT);
        assertEq(registry.latestTotalDifficulty(), INITIAL_TOTAL_DIFFICULTY);
        assertEq(registry.checkpointCount(), 1);
        assertEq(registry.checkpointInterval(), INTERVAL);
        assertEq(registry.confirmationDepth(), CONFIRMATION_DEPTH);
        assertEq(registry.challengePeriod(), CHALLENGE_PERIOD);
    }

    function testSafeGuardianSingletonMigrationFailsClosed() public {
        MockGovernance implementation = new MockGovernance();
        MockGovernance replacement = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(safeGuardian);
        DOMCheckpointRegistry protectedRegistry = new DOMCheckpointRegistry(c);

        assertEq(protectedRegistry.guardianImplementation(), address(implementation));
        assertEq(protectedRegistry.guardianImplementationCodeHash(), address(implementation).codehash);
        safeGuardian.setMasterCopy(address(replacement));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));
    }

    function testSafeGuardianPolicyDriftFailsClosed() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(safeGuardian);
        DOMCheckpointRegistry protectedRegistry = new DOMCheckpointRegistry(c);
        assertTrue(protectedRegistry.guardianControlHealthy());

        safeGuardian.setOwner(0, address(0x102));
        safeGuardian.setOwner(1, address(0x101));
        assertTrue(protectedRegistry.guardianControlHealthy());
        safeGuardian.setOwner(0, address(0x101));
        safeGuardian.setOwner(1, address(0x102));

        safeGuardian.setThreshold(1);
        assertFalse(protectedRegistry.guardianControlHealthy());
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));

        safeGuardian.setThreshold(2);
        safeGuardian.setOwnerCount(4);
        assertFalse(protectedRegistry.guardianControlHealthy());
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));

        safeGuardian.setOwnerCount(3);
        safeGuardian.setModule(address(0xBEEF));
        assertFalse(protectedRegistry.guardianControlHealthy());
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));

        safeGuardian.setModule(address(0));
        safeGuardian.setOwner(1, address(implementation));
        assertFalse(protectedRegistry.guardianControlHealthy());
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));

        safeGuardian.setOwner(1, address(0x102));
        safeGuardian.setGuard(address(0xBEEF));
        assertFalse(protectedRegistry.guardianControlHealthy());
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));

        safeGuardian.setGuard(address(0));
        vm.chainId(1);
        assertFalse(protectedRegistry.guardianControlHealthy());
        safeGuardian.setFallbackHandler(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        assertFalse(protectedRegistry.guardianControlHealthy());
        installMainnetSafeFallbackHandler();
        assertTrue(protectedRegistry.guardianControlHealthy());
        vm.etch(SAFE_MAINNET_FALLBACK_HANDLER, hex"00");
        assertFalse(protectedRegistry.guardianControlHealthy());
        installMainnetSafeFallbackHandler();
        safeGuardian.setFallbackHandler(address(0xBEEF));
        assertFalse(protectedRegistry.guardianControlHealthy());
    }

    function testSafeGuardianPolicyDriftStopsCheckpointSubmission() public {
        this.newSafeRegistry();
        scratchSafeGuardian.setThreshold(1);
        this.assertGuardianStopsSubmission();
    }

    function testSafeGuardianPolicyDriftStopsCheckpointFinalization() public {
        this.newSafeRegistry();
        this.submitApprovedCandidate();
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        scratchSafeGuardian.setModule(address(0xBEEF));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        scratchProtectedRegistry.finalizeCheckpoint();

        assertEq(scratchProtectedRegistry.latestHeight(), INITIAL_HEIGHT);
        this.assertScratchCandidatePresent();
    }

    function testSafeOwnerReplacementPreservesCandidateAndRequiresExactRestoration() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(safeGuardian);
        DOMCheckpointRegistry protectedRegistry = new DOMCheckpointRegistry(c);
        bytes32 originalOwners = keccak256(abi.encode(address(0x101), address(0x102), address(0x103)));
        assertEq(protectedRegistry.guardianOwnersCommitment(), originalOwners);

        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x65);
        bytes32 statementHash = protectedRegistry.checkpointStatementHash(checkpoint);
        checkpointVerifier.approve(statementHash, proof);
        protectedRegistry.submitCheckpointCandidate(checkpoint, proof);
        uint64 readyAt = _candidateReadyAt(protectedRegistry);
        vm.warp(readyAt);

        safeGuardian.setOwner(0, address(0x104));
        assertFalse(protectedRegistry.guardianControlHealthy());
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        protectedRegistry.finalizeCheckpoint();
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));
        bytes32 preserved = _candidateHash(protectedRegistry);
        uint64 preservedReadyAt = _candidateReadyAt(protectedRegistry);
        assertEq(preserved, statementHash);
        assertEq(preservedReadyAt, readyAt);
        assertEq(protectedRegistry.latestHeight(), INITIAL_HEIGHT);
        assertFalse(protectedRegistry.halted());

        safeGuardian.setOwner(0, address(0x101));
        assertTrue(protectedRegistry.guardianControlHealthy());
        protectedRegistry.finalizeCheckpoint();
        assertEq(protectedRegistry.latestHeight(), checkpoint.height);
        assertEq(protectedRegistry.latestBlock(), checkpoint.blockHash);
    }

    function testCombinedSafeDriftMalformedOwnersAndArbitraryRestoreRemainFailClosed() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(safeGuardian);
        DOMCheckpointRegistry protectedRegistry = new DOMCheckpointRegistry(c);
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x66);
        bytes32 statementHash = protectedRegistry.checkpointStatementHash(checkpoint);
        checkpointVerifier.approve(statementHash, proof);
        protectedRegistry.submitCheckpointCandidate(checkpoint, proof);
        uint64 readyAt = _candidateReadyAt(protectedRegistry);
        vm.warp(readyAt);

        safeGuardian.setOwner(0, address(0x104));
        safeGuardian.setModule(address(0xBEEF));
        safeGuardian.setGuard(address(0xCAFE));
        assertFalse(protectedRegistry.guardianControlHealthy());

        safeGuardian.setModule(address(0));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        protectedRegistry.finalizeCheckpoint();
        safeGuardian.setOwner(0, address(0x101));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        protectedRegistry.finalizeCheckpoint();
        safeGuardian.setGuard(address(0));

        for (uint8 mode = 1; mode <= 4; ++mode) {
            safeGuardian.setOwnersReturnMode(mode);
            assertFalse(protectedRegistry.guardianControlHealthy());
            vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
            protectedRegistry.finalizeCheckpoint();
            vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
            safeGuardian.execute(address(protectedRegistry), abi.encodeCall(DOMCheckpointRegistry.haltPermanently, ()));
        }

        safeGuardian.setOwnersReturnMode(0);
        assertTrue(protectedRegistry.guardianControlHealthy());
        bytes32 preserved = _candidateHash(protectedRegistry);
        uint64 preservedReadyAt = _candidateReadyAt(protectedRegistry);
        assertEq(preserved, statementHash);
        assertEq(preservedReadyAt, readyAt);
        assertEq(protectedRegistry.latestHeight(), INITIAL_HEIGHT);
        assertFalse(protectedRegistry.halted());
        protectedRegistry.finalizeCheckpoint();
        assertEq(protectedRegistry.latestHeight(), checkpoint.height);
    }

    function testFinalizeExternalIdentityFailuresPreserveCandidateForExactRetry() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(safeGuardian);
        DOMCheckpointRegistry protectedRegistry = new DOMCheckpointRegistry(c);
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x63);
        bytes32 statementHash = protectedRegistry.checkpointStatementHash(checkpoint);
        checkpointVerifier.approve(statementHash, proof);
        protectedRegistry.submitCheckpointCandidate(checkpoint, proof);
        bytes32 selected = _candidateHash(protectedRegistry);
        uint64 readyAt = _candidateReadyAt(protectedRegistry);
        assertEq(selected, statementHash);
        vm.warp(readyAt);

        checkpointVerifier.setConfigHash(keccak256("temporary verifier drift"));
        vm.expectRevert(DOMCheckpointRegistry.VerifierChanged.selector);
        protectedRegistry.finalizeCheckpoint();
        bytes32 afterVerifierDrift = _candidateHash(protectedRegistry);
        uint64 preservedReadyAt = _candidateReadyAt(protectedRegistry);
        assertEq(afterVerifierDrift, statementHash);
        assertEq(preservedReadyAt, readyAt);
        assertEq(protectedRegistry.latestHeight(), INITIAL_HEIGHT);
        assertEq(protectedRegistry.checkpointCount(), 1);

        checkpointVerifier.setConfigHash(protectedRegistry.verifierConfigHash());
        safeGuardian.setModule(address(0xBEEF));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        protectedRegistry.finalizeCheckpoint();
        bytes32 afterGuardianDrift = _candidateHash(protectedRegistry);
        uint64 stillReadyAt = _candidateReadyAt(protectedRegistry);
        assertEq(afterGuardianDrift, statementHash);
        assertEq(stillReadyAt, readyAt);
        assertEq(protectedRegistry.latestBlock(), INITIAL_BLOCK);

        safeGuardian.setModule(address(0));
        protectedRegistry.finalizeCheckpoint();
        assertEq(protectedRegistry.latestHeight(), checkpoint.height);
        assertEq(protectedRegistry.latestBlock(), checkpoint.blockHash);
        assertEq(protectedRegistry.latestStateRoot(), checkpoint.stateRoot);
        assertEq(protectedRegistry.checkpointCount(), 2);
        assertEq(_candidateHash(protectedRegistry), bytes32(0));

        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        protectedRegistry.submitCheckpointCandidate(checkpoint, proof);
    }

    function testConstructorRejectsUnsafeSafeGuardianPolicy() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(safeGuardian);

        safeGuardian.setThreshold(1);
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);

        safeGuardian.setThreshold(2);
        safeGuardian.setOwnerCount(2);
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);

        safeGuardian.setOwnerCount(3);
        safeGuardian.setModule(address(0xBEEF));
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);

        safeGuardian.setModule(address(0));
        safeGuardian.setOwner(1, address(implementation));
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);

        safeGuardian.setOwner(1, address(0x102));
        safeGuardian.setGuard(address(0xBEEF));
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);
    }

    function testCandidateWaitsThenFinalizesWithExactWitnessEvent() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(2);
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        vm.recordLogs();
        registry.submitCheckpointCandidate(checkpoint, proof);
        Vm.Log[] memory candidateLogs = vm.getRecordedLogs();
        assertEq(candidateLogs.length, 2);
        _assertCandidateLogs(candidateLogs, checkpoint);
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);
        vm.expectRevert(DOMCheckpointRegistry.TooEarly.selector);
        registry.finalizeCheckpoint();

        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.recordLogs();
        registry.finalizeCheckpoint();
        Vm.Log[] memory finalLogs = vm.getRecordedLogs();
        assertEq(finalLogs.length, 2);
        _assertFinalizedLogs(finalLogs, checkpoint);
        assertEq(registry.latestHeight(), checkpoint.height);
        assertEq(registry.latestBlock(), checkpoint.blockHash);
        assertEq(registry.latestStateRoot(), checkpoint.stateRoot);
        assertEq(registry.latestContextHash(), checkpoint.contextHash);
        assertEq(registry.latestTotalDifficulty(), checkpoint.totalDifficulty);
        assertEq(registry.checkpointCount(), 2);
        assertEq(_candidateHash(registry), bytes32(0));
    }

    function _assertCandidateLogs(Vm.Log[] memory logs, DOMCheckpointRegistry.CheckpointInput memory checkpoint)
        private
        view
    {
        bytes32 candidateSignature = keccak256(
            "CheckpointCandidate(bytes32,uint32,uint64,bytes32,bytes32,bytes32,uint256,uint64,bytes32,uint256,uint64,uint64,bytes32)"
        );
        bytes32 economicsSignature = keccak256("CheckpointCandidateEconomics(bytes32,uint128,uint128,bool)");
        bytes32 statementHash = registry.checkpointStatementHash(checkpoint);
        uint256 candidateCount;
        uint256 economicsCount;
        for (uint256 i; i < logs.length; ++i) {
            assertEq(logs[i].emitter, address(registry));
            if (logs[i].topics[0] == candidateSignature) {
                ++candidateCount;
                assertEq(logs[i].topics[1], DOMAIN);
                assertEq(logs[i].topics[2], bytes32(uint256(NETWORK_MAGIC)));
            } else if (logs[i].topics[0] == economicsSignature) {
                ++economicsCount;
                assertEq(logs[i].topics.length, 2);
                assertEq(logs[i].topics[1], statementHash);
                (uint128 issued, uint128 burned, bool closed) = abi.decode(logs[i].data, (uint128, uint128, bool));
                assertEq(issued, checkpoint.totalIssued);
                assertEq(burned, checkpoint.totalBurned);
                assertTrue(closed == checkpoint.issuanceClosed);
            } else revert("unexpected candidate log");
        }
        assertEq(candidateCount, 1);
        assertEq(economicsCount, 1);
    }

    function _assertFinalizedLogs(Vm.Log[] memory logs, DOMCheckpointRegistry.CheckpointInput memory checkpoint)
        private
        view
    {
        bytes32 checkpointSignature = keccak256("Checkpoint(bytes32,uint32,uint64,bytes32,bytes32,bytes32)");
        bytes32 v2Signature = keccak256("CheckpointFinalizedV2(bytes32,bytes32,uint256,uint128,uint128,bool,uint256)");
        uint256 checkpointCount;
        uint256 v2Count;
        for (uint256 i; i < logs.length; ++i) {
            assertEq(logs[i].emitter, address(registry));
            if (logs[i].topics[0] == checkpointSignature) {
                ++checkpointCount;
                _assertCheckpointLog(logs[i], checkpoint);
            } else if (logs[i].topics[0] == v2Signature) {
                ++v2Count;
                assertEq(logs[i].topics.length, 2);
                assertEq(logs[i].topics[1], registry.checkpointStatementHash(checkpoint));
                (bytes32 contextHash, uint256 difficulty, uint128 issued, uint128 burned, bool closed, uint256 count) =
                    abi.decode(logs[i].data, (bytes32, uint256, uint128, uint128, bool, uint256));
                assertEq(contextHash, checkpoint.contextHash);
                assertEq(difficulty, checkpoint.totalDifficulty);
                assertEq(issued, checkpoint.totalIssued);
                assertEq(burned, checkpoint.totalBurned);
                assertTrue(closed == checkpoint.issuanceClosed);
                assertEq(count, 2);
            } else revert("unexpected finalized log");
        }
        assertEq(checkpointCount, 1);
        assertEq(v2Count, 1);
    }

    function testStatementHashBindsEveryPublicField() public view {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory prefix = abi.encode(
            registry.CHECKPOINT_STATEMENT_TYPEHASH(),
            DOMAIN,
            NETWORK_MAGIC,
            registry.NATIVE_STATE_VERSION(),
            registry.TRANSITION_BATCH_VERSION(),
            checkpoint.previousHeight,
            checkpoint.previousBlock,
            checkpoint.previousStateRoot,
            checkpoint.previousContextHash,
            checkpoint.previousTotalDifficulty,
            checkpoint.height,
            checkpoint.blockHash
        );
        bytes32 expected = keccak256(
            bytes.concat(
                prefix,
                abi.encode(
                    checkpoint.stateRoot,
                    checkpoint.contextHash,
                    checkpoint.totalDifficulty,
                    checkpoint.totalIssued,
                    checkpoint.totalBurned,
                    checkpoint.issuanceClosed,
                    checkpoint.confirmationHeight
                ),
                abi.encode(
                    checkpoint.confirmationBlock,
                    checkpoint.confirmationTotalDifficulty,
                    checkpoint.confirmationTimestamp,
                    block.chainid,
                    address(registry),
                    ACTIVATION,
                    registry.checkpointConfigHash()
                )
            )
        );
        assertEq(registry.checkpointStatementHash(checkpoint), expected);
    }

    function testV2StatementHashMatchesRustAndJavaScriptVector() public pure {
        bytes32 typeHash = keccak256(
            "DOMCheckpointV2(bytes32 bridgeDomain,uint32 domNetworkMagic,uint16 nativeStateVersion,uint16 transitionBatchVersion,uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,uint256 previousTotalDifficulty,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 domContextHash,uint256 domTotalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp,uint256 ethereumChainId,address registry,bytes32 activationScheduleCommitment,bytes32 checkpointConfigHash)"
        );
        bytes memory prefix = abi.encode(
            typeHash,
            bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222)),
            uint32(2_712_847_316),
            uint16(2),
            uint16(3),
            uint64(100_000),
            bytes32(uint256(0x9999999999999999999999999999999999999999999999999999999999999999)),
            bytes32(uint256(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)),
            bytes32(uint256(0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee)),
            uint256(1_000_000),
            uint64(100_360),
            bytes32(uint256(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb))
        );
        bytes32 actual = keccak256(
            bytes.concat(
                prefix,
                abi.encode(
                    bytes32(uint256(0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)),
                    bytes32(uint256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)),
                    uint256(1_000_360),
                    uint64(100_390),
                    bytes32(uint256(0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd)),
                    uint256(1_000_390),
                    uint64(1_700_000_000),
                    uint256(1),
                    address(0x1111111111111111111111111111111111111111),
                    bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333)),
                    bytes32(uint256(0x4ab7848ffc06d09ea7462a0ff65ec55e364749839a79a71815171dd1543a1615))
                )
            )
        );
        assertEq(actual, 0xaea1d132059ed25184d27671e5c52061f53f6f767074d6aa10c0ce35fc11249e);
    }

    function testCompetitionUsesConfirmationWorkAndTieBreakWithoutResettingWindow() public {
        DOMCheckpointRegistry.CheckpointInput memory first = nextCheckpoint();
        approveAndSubmit(first, markerProof(1));
        uint64 readyAt = _candidateReadyAt(registry);

        DOMCheckpointRegistry.CheckpointInput memory worse = nextCheckpoint();
        worse.blockHash = keccak256("worse target");
        worse.confirmationBlock = keccak256("worse confirmation");
        worse.confirmationTotalDifficulty--;
        // This proof is deliberately not approved: local rank rejection must
        // happen before the expensive verifier boundary.
        vm.expectRevert(DOMCheckpointRegistry.CandidateNotBetter.selector);
        registry.submitCheckpointCandidate(worse, markerProof(2));

        DOMCheckpointRegistry.CheckpointInput memory better = nextCheckpoint();
        better.blockHash = keccak256("better target");
        better.stateRoot = keccak256("better state");
        better.confirmationBlock = keccak256("better confirmation");
        better.confirmationTotalDifficulty++;
        checkpointVerifier.approve(registry.checkpointStatementHash(better), markerProof(3));
        registry.submitCheckpointCandidate(better, markerProof(3));
        uint64 readyAtAfter = _candidateReadyAt(registry);
        bytes32 selectedBlock = _candidateBlock(registry);
        assertEq(readyAtAfter, readyAt);
        assertEq(selectedBlock, better.blockHash);

        DOMCheckpointRegistry.CheckpointInput memory tied = nextCheckpoint();
        tied.confirmationTotalDifficulty = better.confirmationTotalDifficulty;
        tied.blockHash = keccak256("tied target");
        tied.stateRoot = keccak256("tied state");
        tied.confirmationBlock = bytes32(uint256(better.confirmationBlock) - 1);
        checkpointVerifier.approve(registry.checkpointStatementHash(tied), markerProof(4));
        registry.submitCheckpointCandidate(tied, markerProof(4));
        selectedBlock = _candidateBlock(registry);
        assertEq(selectedBlock, tied.blockHash);

        DOMCheckpointRegistry.CheckpointInput memory losingTie = nextCheckpoint();
        losingTie.confirmationTotalDifficulty = tied.confirmationTotalDifficulty;
        losingTie.confirmationBlock = bytes32(uint256(tied.confirmationBlock) + 1);
        checkpointVerifier.approve(registry.checkpointStatementHash(losingTie), markerProof(5));
        vm.expectRevert(DOMCheckpointRegistry.CandidateNotBetter.selector);
        registry.submitCheckpointCandidate(losingTie, markerProof(5));
    }

    function testExactRankTieUsesStatementHashNotArrivalOrder() public {
        DOMCheckpointRegistry.CheckpointInput memory left = nextCheckpoint();
        left.blockHash = keccak256("exact-rank left target");
        left.stateRoot = keccak256("exact-rank left state");
        left.contextHash = keccak256("exact-rank left context");
        DOMCheckpointRegistry.CheckpointInput memory right = nextCheckpoint();
        right.blockHash = keccak256("exact-rank right target");
        right.stateRoot = keccak256("exact-rank right state");
        right.contextHash = keccak256("exact-rank right context");

        bytes32 leftHash = registry.checkpointStatementHash(left);
        bytes32 rightHash = registry.checkpointStatementHash(right);
        DOMCheckpointRegistry.CheckpointInput memory higher = left;
        DOMCheckpointRegistry.CheckpointInput memory lower = right;
        if (uint256(leftHash) < uint256(rightHash)) {
            higher = right;
            lower = left;
        }
        bytes32 lowerHash = registry.checkpointStatementHash(lower);
        bytes memory firstProof = markerProof(0x66);
        bytes memory secondProof = markerProof(0x67);
        checkpointVerifier.approve(registry.checkpointStatementHash(higher), firstProof);
        registry.submitCheckpointCandidate(higher, firstProof);
        uint64 readyAt = _candidateReadyAt(registry);
        checkpointVerifier.approve(lowerHash, secondProof);
        registry.submitCheckpointCandidate(lower, secondProof);
        bytes32 selected = _candidateHash(registry);
        uint64 unchangedReadyAt = _candidateReadyAt(registry);
        assertEq(selected, lowerHash);
        assertEq(unchangedReadyAt, readyAt);

        vm.expectRevert(DOMCheckpointRegistry.CandidateNotBetter.selector);
        registry.submitCheckpointCandidate(higher, firstProof);
    }

    function testWindowClosesAndProofCannotReplayAfterFinalization() public {
        DOMCheckpointRegistry.CheckpointInput memory first = nextCheckpoint();
        bytes memory proof = markerProof(1);
        approveAndSubmit(first, proof);
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        bytes32 firstBlock = first.blockHash;
        DOMCheckpointRegistry.CheckpointInput memory better = nextCheckpoint();
        better.blockHash = keccak256("late target");
        better.stateRoot = keccak256("late state");
        better.confirmationBlock = keccak256("late confirmation");
        better.confirmationTotalDifficulty++;
        // A closed window is also terminal before proof verification.
        vm.expectRevert(DOMCheckpointRegistry.CandidateWindowClosed.selector);
        registry.submitCheckpointCandidate(better, markerProof(2));
        registry.finalizeCheckpoint();
        assertEq(registry.latestBlock(), firstBlock);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(first, proof);
        vm.expectRevert(DOMCheckpointRegistry.NoCandidate.selector);
        registry.finalizeCheckpoint();
    }

    function testChallengeTimestampOverflowUsesProtocolError() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x7a);
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        vm.warp(type(uint64).max);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, proof);
    }

    function testProofBindsMutationsAndPredecessor() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(6);
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        DOMCheckpointRegistry.CheckpointInput memory changed = nextCheckpoint();
        changed.blockHash = keccak256("substituted block");
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.stateRoot = keccak256("substituted state");
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.contextHash = keccak256("substituted context");
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.totalDifficulty++;
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.confirmationBlock = keccak256("substituted confirmation");
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.confirmationTotalDifficulty++;
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.confirmationTimestamp = 2;
        vm.warp(2);
        _expectInvalidProof(changed, proof);
        changed = nextCheckpoint();
        changed.previousHeight--;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.previousBlock = keccak256("wrong previous block");
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.previousStateRoot = keccak256("wrong previous state");
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.previousContextHash = keccak256("wrong previous context");
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.previousTotalDifficulty--;
        _expectInvalidCheckpoint(changed);
    }

    function testCheckpointProofCannotReplayAcrossRegistryDomainOrActivationDeployment() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x61);
        bytes32 authorizedStatement = registry.checkpointStatementHash(checkpoint);
        checkpointVerifier.approve(authorizedStatement, proof);

        uint256 authorizedChainId = block.chainid;
        vm.chainId(authorizedChainId + 1);
        assertTrue(registry.checkpointStatementHash(checkpoint) != authorizedStatement);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        registry.submitCheckpointCandidate(checkpoint, proof);
        // chainid is invariant in real EVM execution. via-IR may therefore CSE
        // block.chainid across the vm.chainId cheatcode; restore the explicit
        // fixture chain rather than rereading the cached expression.
        vm.chainId(31_337);

        _assertActivationDeploymentRejectsReplay();
        _assertDomainDeploymentRejectsReplay();

        // Neither failed replay consumes the proof authorized for this exact
        // registry/domain/activation tuple.
        bytes32 restoredStatement = registry.checkpointStatementHash(checkpoint);
        assertEq(restoredStatement, authorizedStatement);
        checkpointVerifier.approve(restoredStatement, proof);
        registry.submitCheckpointCandidate(checkpoint, proof);
        assertEq(_candidateHash(registry), authorizedStatement);
    }

    function _assertActivationDeploymentRejectsReplay() private {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x62);
        bytes32 authorizedStatement = registry.checkpointStatementHash(checkpoint);
        checkpointVerifier.approve(authorizedStatement, proof);
        DOMCheckpointRegistry.Config memory otherConfig = config(checkpointVerifier);
        otherConfig.activationScheduleCommitment = keccak256("other checkpoint activation schedule");
        DOMCheckpointRegistry otherActivation = new DOMCheckpointRegistry(otherConfig);
        assertTrue(otherActivation.checkpointConfigHash() != registry.checkpointConfigHash());
        assertTrue(otherActivation.checkpointStatementHash(checkpoint) != authorizedStatement);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        otherActivation.submitCheckpointCandidate(checkpoint, proof);
    }

    function _assertDomainDeploymentRejectsReplay() private {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x63);
        bytes32 authorizedStatement = registry.checkpointStatementHash(checkpoint);
        checkpointVerifier.approve(authorizedStatement, proof);
        DOMCheckpointRegistry.Config memory otherConfig = config(checkpointVerifier);
        otherConfig.bridgeDomain = keccak256("other checkpoint bridge domain");
        DOMCheckpointRegistry otherDomain = new DOMCheckpointRegistry(otherConfig);
        assertTrue(otherDomain.checkpointConfigHash() != registry.checkpointConfigHash());
        assertTrue(otherDomain.checkpointStatementHash(checkpoint) != authorizedStatement);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        otherDomain.submitCheckpointCandidate(checkpoint, proof);
    }

    function testMalformedInputsFailWithoutMovingState() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, "");
        bytes memory oversizedProof = new bytes(registry.MAX_PROOF_BYTES() + 1);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, oversizedProof);
        bytes memory truncatedProof = new bytes(registry.EVM_PROOF_BYTES() - 1);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, truncatedProof);
        bytes memory wrongSelector = markerProof(1);
        wrongSelector[0] ^= 0x01;
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, wrongSelector);
        assertEq(_candidateHash(registry), bytes32(0));
        DOMCheckpointRegistry.CheckpointInput memory changed = nextCheckpoint();
        changed.height++;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.confirmationHeight++;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.blockHash = bytes32(0);
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.stateRoot = bytes32(0);
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.contextHash = bytes32(0);
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.contextHash = changed.previousContextHash;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.totalDifficulty = INITIAL_TOTAL_DIFFICULTY;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.confirmationBlock = bytes32(0);
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.confirmationBlock = changed.blockHash;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.confirmationTotalDifficulty = changed.totalDifficulty;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.confirmationTimestamp = 0;
        _expectInvalidCheckpoint(changed);
        changed = nextCheckpoint();
        changed.confirmationTimestamp = uint64(block.timestamp + 1);
        _expectInvalidCheckpoint(changed);
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);
        assertEq(_candidateHash(registry), bytes32(0));
    }

    function testVerifierAndGuardianFailClosed() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        approveAndSubmit(checkpoint, markerProof(0x12));
        checkpointVerifier.setConfigHash(keccak256("changed verifier configuration"));
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.expectRevert(DOMCheckpointRegistry.VerifierChanged.selector);
        registry.finalizeCheckpoint();

        setUp();
        checkpoint = nextCheckpoint();
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), markerProof(0x34));
        vm.etch(address(checkpointVerifier), hex"00");
        vm.expectRevert(DOMCheckpointRegistry.VerifierChanged.selector);
        registry.submitCheckpointCandidate(checkpoint, markerProof(0x34));

        setUp();
        vm.etch(address(guardian), hex"00");
        vm.prank(address(guardian));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        registry.haltPermanently();
    }

    function testMutableVerifierCapabilityCannotAdvanceAndExactRestorationRetries() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(0x64);
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        checkpointVerifier.setCapability(keccak256("USDOM_FINALIZED_BURN_PROOF_V1"));
        vm.expectRevert(DOMCheckpointRegistry.VerifierChanged.selector);
        registry.submitCheckpointCandidate(checkpoint, proof);
        assertEq(_candidateHash(registry), bytes32(0));
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);

        checkpointVerifier.setCapability(registry.PROOF_ACCEPTED());
        registry.submitCheckpointCandidate(checkpoint, proof);
        assertEq(_candidateHash(registry), registry.checkpointStatementHash(checkpoint));
    }

    function testVerifierMustReturnExactAcceptanceMagic() public {
        HostileDOMCheckpointVerifier hostile = new HostileDOMCheckpointVerifier();
        DOMCheckpointRegistry guarded = new DOMCheckpointRegistry(config(hostile));
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.RevertCall);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.ShortReturn);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.TrailingByteReturn);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.OversizedReturn);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.ReturnBomb);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.Accept);
        guarded.submitCheckpointCandidate(checkpoint, markerProof(1));
        assertEq(guarded.latestHeight(), INITIAL_HEIGHT);
    }

    function testVerifierConfigReturnBombFailsClosedDuringConstruction() public {
        ReturnBombConfigDOMCheckpointVerifier hostile = new ReturnBombConfigDOMCheckpointVerifier();
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(config(hostile));
    }

    function testPermanentHaltStopsSubmissionAndFinalization() public {
        vm.expectRevert(DOMCheckpointRegistry.Unauthorized.selector);
        registry.haltPermanently();
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        approveAndSubmit(checkpoint, markerProof(1));
        vm.prank(address(guardian));
        registry.haltPermanently();
        assertTrue(registry.halted());
        vm.expectRevert(DOMCheckpointRegistry.IsHalted.selector);
        registry.submitCheckpointCandidate(checkpoint, markerProof(1));
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.expectRevert(DOMCheckpointRegistry.IsHalted.selector);
        registry.finalizeCheckpoint();
    }

    function testGracefulShutdownRequiresFinalizedClosureAndZeroCirculation() public {
        vm.expectRevert(DOMCheckpointRegistry.NotGracefullyClosable.selector);
        registry.finalizeGracefulShutdown();

        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        checkpoint.totalIssued = 7;
        checkpoint.totalBurned = 6;
        checkpoint.issuanceClosed = true;
        approveAndSubmit(checkpoint, markerProof(31));
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        registry.finalizeCheckpoint();
        assertTrue(registry.latestIssuanceClosed());
        vm.expectRevert(DOMCheckpointRegistry.NotGracefullyClosable.selector);
        registry.finalizeGracefulShutdown();
    }

    function testFinalizedIssuanceClosurePermanentlyFreezesTotalIssued() public {
        DOMCheckpointRegistry.CheckpointInput memory closing = nextCheckpoint();
        closing.totalIssued = 7;
        closing.totalBurned = 6;
        closing.issuanceClosed = true;
        approveAndSubmit(closing, markerProof(33));
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        registry.finalizeCheckpoint();

        DOMCheckpointRegistry.CheckpointInput memory later = closing;
        later.previousHeight = closing.height;
        later.previousBlock = closing.blockHash;
        later.previousStateRoot = closing.stateRoot;
        later.previousContextHash = closing.contextHash;
        later.previousTotalDifficulty = closing.totalDifficulty;
        later.height = closing.height + INTERVAL;
        later.blockHash = keccak256("DOM checkpoint after issuance closure");
        later.stateRoot = keccak256("DOM state after issuance closure");
        later.contextHash = keccak256("DOM context after issuance closure");
        later.totalDifficulty = closing.totalDifficulty + INTERVAL;
        later.totalIssued = closing.totalIssued + 1;
        later.totalBurned = closing.totalBurned + 1;
        later.confirmationHeight = later.height + CONFIRMATION_DEPTH;
        later.confirmationBlock = keccak256("DOM confirmation after issuance closure");
        later.confirmationTotalDifficulty = later.totalDifficulty + CONFIRMATION_DEPTH;
        later.confirmationTimestamp = uint64(block.timestamp);

        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(later, markerProof(34));
    }

    function testGracefulShutdownIsPermissionlessProofAuthorizedAndDistinctFromEmergency() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        checkpoint.totalIssued = 7;
        checkpoint.totalBurned = 7;
        checkpoint.issuanceClosed = true;
        approveAndSubmit(checkpoint, markerProof(32));
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        registry.finalizeCheckpoint();

        vm.prank(address(0xA11CE));
        registry.finalizeGracefulShutdown();
        assertTrue(registry.halted());
        assertTrue(registry.gracefullyShutdown());
        vm.expectRevert(DOMCheckpointRegistry.IsHalted.selector);
        vm.prank(address(guardian));
        registry.haltPermanently();
    }

    function testEmergencyHaltNeverClaimsGracefulShutdown() public {
        vm.prank(address(guardian));
        registry.haltPermanently();
        assertTrue(registry.halted());
        assertFalse(registry.gracefullyShutdown());
    }

    function testConstructorAndMainnetPolicyFailClosed() public {
        assertEq(registry.SAFE_MAINNET_SINGLETON(), 0x41675C099F32341bf84BFc5382aF534df5C7461a);
        assertEq(
            registry.SAFE_MAINNET_SINGLETON_CODE_HASH(),
            0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4
        );
        assertEq(
            registry.SAFE_MAINNET_PROXY_CODE_HASH(),
            0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c
        );
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.bridgeDomain = bytes32(0);
        _expectInvalidConfig(c);
        c = config(IDOMCheckpointVerifier(address(new ZeroConfigDOMCheckpointVerifier())));
        _expectInvalidConfig(c);
        c = config(IDOMCheckpointVerifier(address(new BurnCapabilityOnCheckpointInterface())));
        _expectInvalidConfig(c);
        c = config(IDOMCheckpointVerifier(address(new MalformedCheckpointCapabilityVerifier())));
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.activationEmptyStateRoot = keccak256("wrong");
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.firstV4Height++;
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.checkpointInterval = 0;
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.checkpointInterval = uint32(registry.MAX_CHECKPOINT_INTERVAL() + 1);
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.confirmationDepth = 0;
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.confirmationDepth = INTERVAL + 1;
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.challengePeriod = uint64(registry.MIN_CHALLENGE_PERIOD() - 1);
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.challengePeriod = uint64(registry.MAX_CHALLENGE_PERIOD() + 1);
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.initialTotalDifficulty = 0;
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.initialContextHash = bytes32(0);
        _expectInvalidConfig(c);
        c = config(checkpointVerifier);
        c.guardian = address(0xBEEF);
        _expectInvalidConfig(c);
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setFallbackHandler(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        c = config(checkpointVerifier);
        installMainnetSafeFallbackHandler();
        vm.chainId(1);
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);
        c.guardian = address(safeGuardian);
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);
    }

    function testFuzzUnapprovedCandidateCannotMoveState(bytes32 blockHash, bytes32 stateRoot, bytes32 confirmation)
        public
    {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        checkpoint.blockHash =
            blockHash != bytes32(0) && blockHash != INITIAL_BLOCK ? blockHash : keccak256("fuzz block");
        checkpoint.stateRoot = stateRoot != bytes32(0) ? stateRoot : keccak256("fuzz state");
        checkpoint.confirmationBlock = confirmation != bytes32(0) && confirmation != checkpoint.blockHash
            ? confirmation
            : keccak256("fuzz confirmation");
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        registry.submitCheckpointCandidate(checkpoint, markerProof(1));
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);
        assertEq(_candidateHash(registry), bytes32(0));
    }

    function _expectInvalidProof(DOMCheckpointRegistry.CheckpointInput memory checkpoint, bytes memory proof) private {
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        registry.submitCheckpointCandidate(checkpoint, proof);
    }

    function _candidateHash(DOMCheckpointRegistry source) private view returns (bytes32 candidateHash) {
        return _candidateWord(source, 0);
    }

    function _candidateReadyAt(DOMCheckpointRegistry source) private view returns (uint64) {
        return uint64(uint256(_candidateWord(source, 2)));
    }

    function _candidateBlock(DOMCheckpointRegistry source) private view returns (bytes32) {
        return _candidateWord(source, 3);
    }

    function _candidateWord(DOMCheckpointRegistry source, uint256 index) private view returns (bytes32 word) {
        (bool ok, bytes memory result) = address(source).staticcall(abi.encodeWithSignature("candidate()"));
        assertTrue(ok);
        assertEq(result.length, 13 * 32);
        assembly ("memory-safe") {
            word := mload(add(add(result, 32), mul(index, 32)))
        }
    }

    function assertScratchCandidatePresent() external view {
        assertEq(msg.sender, address(this));
        assertTrue(_candidateHash(scratchProtectedRegistry) != bytes32(0));
    }

    function newSafeRegistry() external {
        assertEq(msg.sender, address(this));
        MockGovernance implementation = new MockGovernance();
        scratchSafeGuardian = new MockMutableSingletonControl(address(implementation));
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.guardian = address(scratchSafeGuardian);
        scratchProtectedRegistry = new DOMCheckpointRegistry(c);
    }

    function assertGuardianStopsSubmission() external {
        assertEq(msg.sender, address(this));
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(1);
        checkpointVerifier.approve(scratchProtectedRegistry.checkpointStatementHash(checkpoint), proof);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        scratchProtectedRegistry.submitCheckpointCandidate(checkpoint, "");
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        scratchProtectedRegistry.submitCheckpointCandidate(checkpoint, proof);
    }

    function submitApprovedCandidate() external {
        assertEq(msg.sender, address(this));
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = markerProof(1);
        checkpointVerifier.approve(scratchProtectedRegistry.checkpointStatementHash(checkpoint), proof);
        scratchProtectedRegistry.submitCheckpointCandidate(checkpoint, proof);
    }

    function _expectInvalidCheckpoint(DOMCheckpointRegistry.CheckpointInput memory checkpoint) private {
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, markerProof(1));
    }

    function _expectInvalidConfig(DOMCheckpointRegistry.Config memory c) private {
        vm.expectRevert(DOMCheckpointRegistry.InvalidConfiguration.selector);
        new DOMCheckpointRegistry(c);
    }

    function _assertCheckpointLog(Vm.Log memory entry, DOMCheckpointRegistry.CheckpointInput memory checkpoint)
        private
        view
    {
        assertEq(entry.emitter, address(registry));
        assertEq(entry.topics.length, 3);
        assertEq(entry.topics[0], keccak256("Checkpoint(bytes32,uint32,uint64,bytes32,bytes32,bytes32)"));
        assertEq(entry.topics[1], DOMAIN);
        assertEq(entry.topics[2], bytes32(uint256(NETWORK_MAGIC)));
        (uint64 height, bytes32 blockHash, bytes32 stateRoot, bytes32 configHash) =
            abi.decode(entry.data, (uint64, bytes32, bytes32, bytes32));
        assertEq(height, checkpoint.height);
        assertEq(blockHash, checkpoint.blockHash);
        assertEq(stateRoot, checkpoint.stateRoot);
        assertEq(configHash, registry.checkpointConfigHash());
    }
}
