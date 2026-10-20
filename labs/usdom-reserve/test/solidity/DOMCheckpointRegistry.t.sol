// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {DOMCheckpointRegistry, IDOMCheckpointVerifier} from "../../contracts/DOMCheckpointRegistry.sol";
import {MockGovernance} from "./Mocks.sol";
import {TestBase, Vm} from "./TestBase.sol";

contract MockDOMCheckpointVerifier is IDOMCheckpointVerifier {
    bytes32 public override verifierConfigHash = keccak256("DOM checkpoint verifier test configuration");
    mapping(bytes32 => bool) private accepted;

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function setConfigHash(bytes32 value) external {
        verifierConfigHash = value;
    }

    function verifyDOMCheckpoint(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
        return accepted[keccak256(abi.encode(statementHash, proof))] ? keccak256("DOM_CHECKPOINT_PROOF_V2") : bytes32(0);
    }
}

contract HostileDOMCheckpointVerifier is IDOMCheckpointVerifier {
    enum Mode {
        Reject,
        Accept,
        RevertCall,
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
        if (mode == Mode.OversizedReturn) {
            bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V2");
            assembly ("memory-safe") {
                mstore(0, accepted)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (mode == Mode.ReturnBomb) {
            bytes32 accepted = keccak256("DOM_CHECKPOINT_PROOF_V2");
            assembly ("memory-safe") {
                mstore(0, accepted)
                return(0, 0x100000)
            }
        }
        return mode == Mode.Accept ? keccak256("DOM_CHECKPOINT_PROOF_V2") : bytes32(0);
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
        return keccak256("DOM_CHECKPOINT_PROOF_V2");
    }
}

contract ZeroConfigDOMCheckpointVerifier is IDOMCheckpointVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        return bytes32(0);
    }

    function verifyDOMCheckpoint(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("DOM_CHECKPOINT_PROOF_V2");
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
            confirmationHeight: INITIAL_HEIGHT + INTERVAL + CONFIRMATION_DEPTH,
            confirmationBlock: keccak256("DOM checkpoint confirmation block"),
            confirmationTotalDifficulty: INITIAL_TOTAL_DIFFICULTY + INTERVAL + CONFIRMATION_DEPTH,
            confirmationTimestamp: 1
        });
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
            FIRST_V4_HEIGHT,
            INITIAL_STATE,
            ACTIVATION
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
                address(guardian),
                address(guardian).codehash,
                INITIAL_HEIGHT,
                INITIAL_BLOCK,
                INITIAL_STATE,
                INITIAL_CONTEXT,
                INITIAL_TOTAL_DIFFICULTY
            )
        );
        bytes32 expected = keccak256(abi.encode(registry.CHECKPOINT_CONFIG_TYPEHASH(), identityHash, bootstrapHash));
        assertEq(registry.checkpointConfigHash(), expected);
        assertEq(vm.load(address(registry), bytes32(0)), expected);
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

    function testCandidateWaitsThenFinalizesWithExactWitnessEvent() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = hex"010203";
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        vm.recordLogs();
        registry.submitCheckpointCandidate(checkpoint, proof);
        Vm.Log[] memory candidateLogs = vm.getRecordedLogs();
        assertEq(candidateLogs.length, 1);
        assertEq(
            candidateLogs[0].topics[0],
            keccak256(
                "CheckpointCandidate(bytes32,uint32,uint64,bytes32,bytes32,bytes32,uint256,uint64,bytes32,uint256,uint64,uint64,bytes32)"
            )
        );
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);
        vm.expectRevert(DOMCheckpointRegistry.TooEarly.selector);
        registry.finalizeCheckpoint();

        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.recordLogs();
        registry.finalizeCheckpoint();
        Vm.Log[] memory finalLogs = vm.getRecordedLogs();
        assertEq(finalLogs.length, 1);
        _assertCheckpointLog(finalLogs[0], checkpoint);
        assertEq(registry.latestHeight(), checkpoint.height);
        assertEq(registry.latestBlock(), checkpoint.blockHash);
        assertEq(registry.latestStateRoot(), checkpoint.stateRoot);
        assertEq(registry.latestContextHash(), checkpoint.contextHash);
        assertEq(registry.latestTotalDifficulty(), checkpoint.totalDifficulty);
        assertEq(registry.checkpointCount(), 2);
        (bytes32 candidateHash,,,,,,,,,,) = registry.candidate();
        assertEq(candidateHash, bytes32(0));
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
                    checkpoint.confirmationHeight,
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
        approveAndSubmit(first, hex"01");
        (,, uint64 readyAt,,,,,,,,) = registry.candidate();

        DOMCheckpointRegistry.CheckpointInput memory worse = nextCheckpoint();
        worse.blockHash = keccak256("worse target");
        worse.confirmationBlock = keccak256("worse confirmation");
        worse.confirmationTotalDifficulty--;
        checkpointVerifier.approve(registry.checkpointStatementHash(worse), hex"02");
        vm.expectRevert(DOMCheckpointRegistry.CandidateNotBetter.selector);
        registry.submitCheckpointCandidate(worse, hex"02");

        DOMCheckpointRegistry.CheckpointInput memory better = nextCheckpoint();
        better.blockHash = keccak256("better target");
        better.stateRoot = keccak256("better state");
        better.confirmationBlock = keccak256("better confirmation");
        better.confirmationTotalDifficulty++;
        checkpointVerifier.approve(registry.checkpointStatementHash(better), hex"03");
        registry.submitCheckpointCandidate(better, hex"03");
        (,, uint64 readyAtAfter, bytes32 selectedBlock,,,,,,,) = registry.candidate();
        assertEq(readyAtAfter, readyAt);
        assertEq(selectedBlock, better.blockHash);

        DOMCheckpointRegistry.CheckpointInput memory tied = nextCheckpoint();
        tied.confirmationTotalDifficulty = better.confirmationTotalDifficulty;
        tied.blockHash = keccak256("tied target");
        tied.stateRoot = keccak256("tied state");
        tied.confirmationBlock = bytes32(uint256(better.confirmationBlock) - 1);
        checkpointVerifier.approve(registry.checkpointStatementHash(tied), hex"04");
        registry.submitCheckpointCandidate(tied, hex"04");
        (,,, selectedBlock,,,,,,,) = registry.candidate();
        assertEq(selectedBlock, tied.blockHash);

        DOMCheckpointRegistry.CheckpointInput memory losingTie = nextCheckpoint();
        losingTie.confirmationTotalDifficulty = tied.confirmationTotalDifficulty;
        losingTie.confirmationBlock = bytes32(uint256(tied.confirmationBlock) + 1);
        checkpointVerifier.approve(registry.checkpointStatementHash(losingTie), hex"05");
        vm.expectRevert(DOMCheckpointRegistry.CandidateNotBetter.selector);
        registry.submitCheckpointCandidate(losingTie, hex"05");
    }

    function testWindowClosesAndProofCannotReplayAfterFinalization() public {
        DOMCheckpointRegistry.CheckpointInput memory first = nextCheckpoint();
        bytes memory proof = hex"01";
        approveAndSubmit(first, proof);
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        bytes32 firstBlock = first.blockHash;
        DOMCheckpointRegistry.CheckpointInput memory better = nextCheckpoint();
        better.blockHash = keccak256("late target");
        better.stateRoot = keccak256("late state");
        better.confirmationBlock = keccak256("late confirmation");
        better.confirmationTotalDifficulty++;
        checkpointVerifier.approve(registry.checkpointStatementHash(better), hex"02");
        vm.expectRevert(DOMCheckpointRegistry.CandidateWindowClosed.selector);
        registry.submitCheckpointCandidate(better, hex"02");
        registry.finalizeCheckpoint();
        assertEq(registry.latestBlock(), firstBlock);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(first, proof);
        vm.expectRevert(DOMCheckpointRegistry.NoCandidate.selector);
        registry.finalizeCheckpoint();
    }

    function testProofBindsMutationsAndPredecessor() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        bytes memory proof = hex"abcd";
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

    function testMalformedInputsFailWithoutMovingState() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, "");
        bytes memory oversizedProof = new bytes(registry.MAX_PROOF_BYTES() + 1);
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, oversizedProof);
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
        (bytes32 candidateHash,,,,,,,,,,) = registry.candidate();
        assertEq(candidateHash, bytes32(0));
    }

    function testVerifierAndGuardianFailClosed() public {
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        approveAndSubmit(checkpoint, hex"12");
        checkpointVerifier.setConfigHash(keccak256("changed verifier configuration"));
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.expectRevert(DOMCheckpointRegistry.VerifierChanged.selector);
        registry.finalizeCheckpoint();

        setUp();
        checkpoint = nextCheckpoint();
        checkpointVerifier.approve(registry.checkpointStatementHash(checkpoint), hex"34");
        vm.etch(address(checkpointVerifier), hex"00");
        vm.expectRevert(DOMCheckpointRegistry.VerifierChanged.selector);
        registry.submitCheckpointCandidate(checkpoint, hex"34");

        setUp();
        vm.etch(address(guardian), hex"00");
        vm.prank(address(guardian));
        vm.expectRevert(DOMCheckpointRegistry.GuardianChanged.selector);
        registry.haltPermanently();
    }

    function testVerifierMustReturnExactAcceptanceMagic() public {
        HostileDOMCheckpointVerifier hostile = new HostileDOMCheckpointVerifier();
        DOMCheckpointRegistry guarded = new DOMCheckpointRegistry(config(hostile));
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = nextCheckpoint();
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, hex"01");
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.RevertCall);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, hex"01");
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.OversizedReturn);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, hex"01");
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.ReturnBomb);
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        guarded.submitCheckpointCandidate(checkpoint, hex"01");
        hostile.setMode(HostileDOMCheckpointVerifier.Mode.Accept);
        guarded.submitCheckpointCandidate(checkpoint, hex"01");
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
        approveAndSubmit(checkpoint, hex"01");
        vm.prank(address(guardian));
        registry.haltPermanently();
        assertTrue(registry.halted());
        vm.expectRevert(DOMCheckpointRegistry.IsHalted.selector);
        registry.submitCheckpointCandidate(checkpoint, hex"01");
        vm.warp(block.timestamp + CHALLENGE_PERIOD);
        vm.expectRevert(DOMCheckpointRegistry.IsHalted.selector);
        registry.finalizeCheckpoint();
    }

    function testConstructorAndMainnetPolicyFailClosed() public {
        DOMCheckpointRegistry.Config memory c = config(checkpointVerifier);
        c.bridgeDomain = bytes32(0);
        _expectInvalidConfig(c);
        c = config(IDOMCheckpointVerifier(address(new ZeroConfigDOMCheckpointVerifier())));
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
        vm.chainId(1);
        c = config(checkpointVerifier);
        vm.expectRevert(DOMCheckpointRegistry.ProductionUnavailable.selector);
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
        registry.submitCheckpointCandidate(checkpoint, hex"01");
        assertEq(registry.latestHeight(), INITIAL_HEIGHT);
        (bytes32 candidateHash,,,,,,,,,,) = registry.candidate();
        assertEq(candidateHash, bytes32(0));
    }

    function _expectInvalidProof(DOMCheckpointRegistry.CheckpointInput memory checkpoint, bytes memory proof) private {
        vm.expectRevert(DOMCheckpointRegistry.InvalidProof.selector);
        registry.submitCheckpointCandidate(checkpoint, proof);
    }

    function _expectInvalidCheckpoint(DOMCheckpointRegistry.CheckpointInput memory checkpoint) private {
        vm.expectRevert(DOMCheckpointRegistry.InvalidCheckpoint.selector);
        registry.submitCheckpointCandidate(checkpoint, hex"01");
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
