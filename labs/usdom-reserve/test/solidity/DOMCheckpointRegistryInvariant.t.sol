// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {DOMCheckpointRegistry} from "../../contracts/DOMCheckpointRegistry.sol";
import {IDOMCheckpointVerifier} from "../../contracts/IDOMCheckpointVerifier.sol";
import {MockGovernance} from "./Mocks.sol";
import {TestBase} from "./TestBase.sol";

contract InvariantCheckpointVerifier is IDOMCheckpointVerifier {
    bytes32 public constant PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V3");
    bytes32 public constant CONFIG = keccak256("checkpoint registry invariant verifier");
    mapping(bytes32 => bool) private accepted;

    function verifierConfigHash() external pure returns (bytes32) {
        return CONFIG;
    }

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function verifyDOMCheckpoint(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
        return accepted[keccak256(abi.encode(statementHash, proof))] ? keccak256("DOM_CHECKPOINT_PROOF_V3") : bytes32(0);
    }
}

contract CheckpointRegistryHandler is TestBase {
    DOMCheckpointRegistry public immutable registry;
    InvariantCheckpointVerifier public immutable verifier;
    MockGovernance public immutable guardian;

    uint256 private serial;
    uint256 public finalizedCount;
    uint64 public ghostLatestHeight;
    bytes32 public ghostLatestBlock;
    bytes32 public ghostLatestStateRoot;
    bytes32 public ghostLatestContextHash;
    uint256 public ghostLatestTotalDifficulty;
    uint128 public ghostLatestTotalIssued;
    uint128 public ghostLatestTotalBurned;
    bool public ghostLatestIssuanceClosed;
    uint64 public ghostCandidateReadyAt;
    bool public ghostHalted;
    bytes32 public haltedLatestBlock;
    bytes32 public haltedCandidateHash;

    constructor(DOMCheckpointRegistry registry_, InvariantCheckpointVerifier verifier_, MockGovernance guardian_) {
        registry = registry_;
        verifier = verifier_;
        guardian = guardian_;
        ghostLatestHeight = registry_.latestHeight();
        ghostLatestBlock = registry_.latestBlock();
        ghostLatestStateRoot = registry_.latestStateRoot();
        ghostLatestContextHash = registry_.latestContextHash();
        ghostLatestTotalDifficulty = registry_.latestTotalDifficulty();
        ghostLatestTotalIssued = registry_.latestTotalIssued();
        ghostLatestTotalBurned = registry_.latestTotalBurned();
        ghostLatestIssuanceClosed = registry_.latestIssuanceClosed();
    }

    function submitBetter(uint256 work, bytes32 entropy) external {
        if (registry.halted()) return;
        bytes32 currentHash = _candidateWord(0);
        uint64 readyAt = uint64(uint256(_candidateWord(2)));
        bytes32 confirmationBlock = _candidateWord(10);
        uint256 confirmationWork = uint256(_candidateWord(11));
        // Once the window closes only finalization may advance the round.
        if (currentHash != bytes32(0) && block.timestamp >= readyAt) return;

        DOMCheckpointRegistry.CheckpointInput memory checkpoint = _nextCheckpoint(work, entropy);
        if (currentHash != bytes32(0)) {
            checkpoint.confirmationTotalDifficulty = confirmationWork + 1 + work % 1_000_000;
            if (checkpoint.confirmationBlock == confirmationBlock) {
                checkpoint.confirmationBlock = keccak256(abi.encode("better confirmation", ++serial, entropy));
            }
        }
        bytes memory proof =
            canonicalRiscZeroProof(keccak256(abi.encode("checkpoint invariant proof", ++serial, entropy)));
        verifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        registry.submitCheckpointCandidate(checkpoint, proof);

        bytes32 selected = _candidateWord(0);
        uint64 selectedReadyAt = uint64(uint256(_candidateWord(2)));
        assertTrue(selected != bytes32(0));
        if (currentHash == bytes32(0)) ghostCandidateReadyAt = selectedReadyAt;
        else assertEq(selectedReadyAt, ghostCandidateReadyAt);
    }

    function finalize() external {
        if (registry.halted()) return;
        bytes32 statementHash = _candidateWord(0);
        uint64 height = uint64(uint256(_candidateWord(1)));
        uint64 readyAt = uint64(uint256(_candidateWord(2)));
        bytes32 blockHash = _candidateWord(3);
        bytes32 stateRoot = _candidateWord(4);
        bytes32 contextHash = _candidateWord(5);
        uint256 totalDifficulty = uint256(_candidateWord(6));
        uint128 totalIssued = uint128(uint256(_candidateWord(7)));
        uint128 totalBurned = uint128(uint256(_candidateWord(8)));
        bool issuanceClosed = registry.candidateIssuanceClosed();
        if (statementHash == bytes32(0) || block.timestamp < readyAt) return;
        if (ghostLatestIssuanceClosed) {
            assertTrue(issuanceClosed);
            assertEq(totalIssued, ghostLatestTotalIssued);
        }
        registry.finalizeCheckpoint();
        ++finalizedCount;
        ghostLatestHeight = height;
        ghostLatestBlock = blockHash;
        ghostLatestStateRoot = stateRoot;
        ghostLatestContextHash = contextHash;
        ghostLatestTotalDifficulty = totalDifficulty;
        ghostLatestTotalIssued = totalIssued;
        ghostLatestTotalBurned = totalBurned;
        ghostLatestIssuanceClosed = issuanceClosed;
        ghostCandidateReadyAt = 0;
    }

    function advance(uint32 elapsed) external {
        vm.warp(block.timestamp + uint256(elapsed) % (uint256(registry.challengePeriod()) * 2 + 1));
    }

    function rejectUnproved(uint256 work, bytes32 entropy) external {
        if (registry.halted()) return;
        bytes32 currentHash = _candidateWord(0);
        uint64 readyAt = uint64(uint256(_candidateWord(2)));
        bytes32 confirmationBlock = _candidateWord(10);
        uint256 confirmationWork = uint256(_candidateWord(11));
        if (currentHash != bytes32(0) && block.timestamp >= readyAt) return;
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = _nextCheckpoint(work, entropy);
        if (currentHash != bytes32(0)) {
            checkpoint.confirmationTotalDifficulty = confirmationWork + 1;
            if (checkpoint.confirmationBlock == confirmationBlock) {
                checkpoint.confirmationBlock = keccak256(abi.encode("unproved confirmation", ++serial, entropy));
            }
        }
        bytes memory proof =
            canonicalRiscZeroProof(keccak256(abi.encode("unapproved checkpoint invariant proof", ++serial, entropy)));
        bytes32 latestBefore = registry.latestBlock();
        bytes32 candidateBefore = _candidateWord(0);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.submitCheckpointCandidate, (checkpoint, proof)));
        assertFalse(ok);
        assertEq(registry.latestBlock(), latestBefore);
        bytes32 candidateAfter = _candidateWord(0);
        assertEq(candidateAfter, candidateBefore);
    }

    function rejectNonLeading(bytes32 entropy) external {
        if (registry.halted()) return;
        bytes32 currentHash = _candidateWord(0);
        uint64 readyAt = uint64(uint256(_candidateWord(2)));
        uint256 currentDifficulty = uint256(_candidateWord(6));
        bytes32 currentConfirmationBlock = _candidateWord(10);
        uint256 currentConfirmationDifficulty = uint256(_candidateWord(11));
        if (currentHash == bytes32(0) || block.timestamp >= readyAt) return;
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = _nextCheckpoint(0, entropy);
        checkpoint.totalDifficulty = currentDifficulty;
        // Equal confirmation work is still eligible to win through the
        // deterministic block/statement tie-breakers. Make the candidate
        // strictly worse on the primary rank so this negative action cannot
        // accidentally submit a legitimate replacement.
        checkpoint.confirmationTotalDifficulty = currentConfirmationDifficulty - 1;
        checkpoint.confirmationBlock = currentConfirmationBlock;
        if (checkpoint.confirmationBlock == checkpoint.blockHash) {
            checkpoint.blockHash = keccak256(abi.encode("non-leading block", ++serial, entropy));
        }
        bytes memory proof =
            canonicalRiscZeroProof(keccak256(abi.encode("non-leading checkpoint invariant proof", ++serial, entropy)));
        verifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.submitCheckpointCandidate, (checkpoint, proof)));
        assertFalse(ok);
        bytes32 candidateAfter = _candidateWord(0);
        assertEq(candidateAfter, currentHash);
    }

    function rejectLateImprovement(uint256 work, bytes32 entropy) external {
        if (registry.halted()) return;
        bytes32 currentHash = _candidateWord(0);
        uint64 readyAt = uint64(uint256(_candidateWord(2)));
        bytes32 confirmationBlock = _candidateWord(10);
        uint256 confirmationWork = uint256(_candidateWord(11));
        if (currentHash == bytes32(0)) return;
        // The mutation is the action under test: a replacement submitted at
        // the exact deadline must fail without changing the selected candidate.
        // forge-lint: disable-next-line(environment-read-across-mutation)
        if (block.timestamp < readyAt) vm.warp(readyAt);
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = _nextCheckpoint(work, entropy);
        checkpoint.confirmationTotalDifficulty = confirmationWork + 1 + work % 1_000_000;
        if (checkpoint.confirmationBlock == confirmationBlock) {
            checkpoint.confirmationBlock = keccak256(abi.encode("late confirmation", ++serial, entropy));
        }
        bytes memory proof =
            canonicalRiscZeroProof(keccak256(abi.encode("late checkpoint invariant proof", ++serial, entropy)));
        verifier.approve(registry.checkpointStatementHash(checkpoint), proof);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.submitCheckpointCandidate, (checkpoint, proof)));
        assertFalse(ok);
        bytes32 candidateAfter = _candidateWord(0);
        assertEq(candidateAfter, currentHash);
    }

    function halt() external {
        if (registry.halted()) return;
        guardian.execute(address(registry), abi.encodeCall(registry.haltPermanently, ()));
        ghostHalted = true;
        haltedLatestBlock = registry.latestBlock();
        haltedCandidateHash = _candidateWord(0);
    }

    function rejectUnauthorizedHalt() external {
        if (registry.halted()) return;
        (bool ok,) = address(registry).call(abi.encodeCall(registry.haltPermanently, ()));
        assertFalse(ok);
    }

    function _candidateWord(uint256 index) public view returns (bytes32 word) {
        (bool ok, bytes memory result) = address(registry).staticcall(abi.encodeWithSignature("candidate()"));
        assertTrue(ok);
        assertEq(result.length, 13 * 32);
        assembly ("memory-safe") {
            word := mload(add(add(result, 32), mul(index, 32)))
        }
    }

    function _nextCheckpoint(uint256 work, bytes32 entropy)
        private
        returns (DOMCheckpointRegistry.CheckpointInput memory checkpoint)
    {
        uint64 previousHeight = registry.latestHeight();
        uint64 height = previousHeight + registry.checkpointInterval();
        uint64 confirmationHeight = height + registry.confirmationDepth();
        uint256 totalDifficulty = registry.latestTotalDifficulty() + 1 + work % 1_000_000;
        uint128 latestIssued = registry.latestTotalIssued();
        uint128 latestBurned = registry.latestTotalBurned();
        bool alreadyClosed = registry.latestIssuanceClosed();
        uint128 issueDelta = alreadyClosed ? 0 : uint128(uint256(entropy) & 0xffff);
        uint128 totalIssued = latestIssued + issueDelta;
        uint256 burnCapacity = uint256(totalIssued) - latestBurned;
        uint128 burnDelta = uint128((uint256(entropy) >> 16) % (burnCapacity + 1));
        bool issuanceClosed = alreadyClosed || ((uint256(entropy) >> 144) & 1 == 1);
        ++serial;
        checkpoint = DOMCheckpointRegistry.CheckpointInput({
            previousHeight: previousHeight,
            previousBlock: registry.latestBlock(),
            previousStateRoot: registry.latestStateRoot(),
            previousContextHash: registry.latestContextHash(),
            previousTotalDifficulty: registry.latestTotalDifficulty(),
            height: height,
            blockHash: keccak256(abi.encode("checkpoint block", serial, entropy)),
            stateRoot: keccak256(abi.encode("checkpoint state", serial, entropy)),
            contextHash: keccak256(abi.encode("checkpoint context", serial, entropy)),
            totalDifficulty: totalDifficulty,
            totalIssued: totalIssued,
            totalBurned: latestBurned + burnDelta,
            issuanceClosed: issuanceClosed,
            confirmationHeight: confirmationHeight,
            confirmationBlock: keccak256(abi.encode("checkpoint confirmation", serial, entropy)),
            confirmationTotalDifficulty: totalDifficulty + 1 + work % 1_000_000,
            // A bounded invariant campaign cannot approach uint64 timestamps.
            // forge-lint: disable-next-line(unsafe-typecast)
            confirmationTimestamp: uint64(block.timestamp)
        });
    }
}

contract DOMCheckpointRegistryInvariantTest is TestBase {
    bytes32 private constant DOMAIN = keccak256("checkpoint registry invariant bridge domain");
    bytes32 private constant DOM_CHAIN_ID = keccak256("checkpoint registry invariant chain ID");
    bytes32 private constant ACTIVATION = keccak256("checkpoint registry invariant activation schedule");
    bytes32 private constant INITIAL_BLOCK = keccak256("checkpoint registry invariant initial block");
    bytes32 private constant INITIAL_STATE = keccak256("checkpoint registry invariant initial state");
    bytes32 private constant INITIAL_CONTEXT = keccak256("checkpoint registry invariant context");
    uint32 private constant NETWORK_MAGIC = 0xA1B2C3D4;
    uint64 private constant INITIAL_HEIGHT = 100_000;
    uint32 private constant INTERVAL = 360;
    uint32 private constant CONFIRMATION_DEPTH = 30;
    uint64 private constant CHALLENGE_PERIOD = 2 days;
    uint256 private constant INITIAL_TOTAL_DIFFICULTY = 1_000_000;

    InvariantCheckpointVerifier private verifier;
    MockGovernance private guardian;
    DOMCheckpointRegistry private registry;
    CheckpointRegistryHandler public handler;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        verifier = new InvariantCheckpointVerifier();
        guardian = new MockGovernance();
        registry = new DOMCheckpointRegistry(
            DOMCheckpointRegistry.Config({
                bridgeDomain: DOMAIN,
                domNetworkMagic: NETWORK_MAGIC,
                domChainId: DOM_CHAIN_ID,
                firstV4Height: INITIAL_HEIGHT + 1,
                activationEmptyStateRoot: INITIAL_STATE,
                activationScheduleCommitment: ACTIVATION,
                checkpointInterval: INTERVAL,
                confirmationDepth: CONFIRMATION_DEPTH,
                challengePeriod: CHALLENGE_PERIOD,
                verifier: verifier,
                guardian: address(guardian),
                initialHeight: INITIAL_HEIGHT,
                initialBlock: INITIAL_BLOCK,
                initialStateRoot: INITIAL_STATE,
                initialContextHash: INITIAL_CONTEXT,
                initialTotalDifficulty: INITIAL_TOTAL_DIFFICULTY
            })
        );
        handler = new CheckpointRegistryHandler(registry, verifier, guardian);
    }

    function targetContracts() public view returns (address[] memory result) {
        result = new address[](1);
        result[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory result) {
        bytes4[] memory selectors = new bytes4[](8);
        selectors[0] = handler.submitBetter.selector;
        selectors[1] = handler.finalize.selector;
        selectors[2] = handler.advance.selector;
        selectors[3] = handler.rejectUnproved.selector;
        selectors[4] = handler.rejectNonLeading.selector;
        selectors[5] = handler.rejectLateImprovement.selector;
        selectors[6] = handler.halt.selector;
        selectors[7] = handler.rejectUnauthorizedHalt.selector;
        result = new FuzzSelector[](1);
        result[0] = FuzzSelector(address(handler), selectors);
    }

    function invariantCheckpointStateIsAnExactMonotonicPrefix() public view {
        assertEq(registry.latestHeight(), handler.ghostLatestHeight());
        assertEq(registry.latestBlock(), handler.ghostLatestBlock());
        assertEq(registry.latestStateRoot(), handler.ghostLatestStateRoot());
        assertEq(registry.latestContextHash(), handler.ghostLatestContextHash());
        assertEq(registry.latestTotalDifficulty(), handler.ghostLatestTotalDifficulty());
        assertEq(registry.latestTotalIssued(), handler.ghostLatestTotalIssued());
        assertEq(registry.latestTotalBurned(), handler.ghostLatestTotalBurned());
        assertTrue(registry.latestIssuanceClosed() == handler.ghostLatestIssuanceClosed());
        assertEq(registry.latestHeight(), INITIAL_HEIGHT + handler.finalizedCount() * INTERVAL);
        assertEq(registry.checkpointCount(), handler.finalizedCount() + 1);
        assertTrue(registry.latestTotalDifficulty() >= INITIAL_TOTAL_DIFFICULTY);
        assertTrue(registry.latestTotalBurned() <= registry.latestTotalIssued());
        assertTrue(registry.previousTotalIssued() <= registry.latestTotalIssued());
        assertTrue(registry.previousTotalBurned() <= registry.latestTotalBurned());
        assertEq(vm.load(address(registry), bytes32(0)), registry.checkpointConfigHash());
        assertEq(address(registry.verifier()).codehash, registry.verifierCodeHash());
        assertEq(address(guardian).codehash, registry.guardianCodeHash());
        assertEq(registry.verifierConfigHash(), verifier.CONFIG());
    }

    function invariantCandidateIsBoundToTheOnlyOpenRound() public view {
        bytes32 statementHash = handler._candidateWord(0);
        uint64 height = uint64(uint256(handler._candidateWord(1)));
        uint64 readyAt = uint64(uint256(handler._candidateWord(2)));
        bytes32 blockHash = handler._candidateWord(3);
        bytes32 stateRoot = handler._candidateWord(4);
        bytes32 contextHash = handler._candidateWord(5);
        uint256 totalDifficulty = uint256(handler._candidateWord(6));
        uint128 totalIssued = uint128(uint256(handler._candidateWord(7)));
        uint128 totalBurned = uint128(uint256(handler._candidateWord(8)));
        bool issuanceClosed = registry.candidateIssuanceClosed();
        uint64 confirmationHeight = uint64(uint256(handler._candidateWord(9)));
        bytes32 confirmationBlock = handler._candidateWord(10);
        uint256 confirmationTotalDifficulty = uint256(handler._candidateWord(11));
        uint64 confirmationTimestamp = uint64(uint256(handler._candidateWord(12)));
        if (statementHash == bytes32(0)) {
            assertEq(height, 0);
            assertEq(readyAt, 0);
            assertEq(blockHash, bytes32(0));
            assertEq(handler.ghostCandidateReadyAt(), 0);
            return;
        }
        assertEq(height, registry.latestHeight() + INTERVAL);
        assertEq(confirmationHeight, height + CONFIRMATION_DEPTH);
        assertEq(readyAt, handler.ghostCandidateReadyAt());
        assertTrue(blockHash != bytes32(0));
        assertTrue(stateRoot != bytes32(0));
        assertTrue(contextHash != bytes32(0));
        assertTrue(contextHash != registry.latestContextHash());
        assertTrue(totalDifficulty > registry.latestTotalDifficulty());
        assertTrue(totalIssued >= registry.latestTotalIssued());
        assertTrue(totalBurned >= registry.latestTotalBurned());
        assertTrue(totalBurned <= totalIssued);
        if (registry.latestIssuanceClosed()) {
            assertTrue(issuanceClosed);
            assertEq(totalIssued, registry.latestTotalIssued());
        }
        assertTrue(confirmationBlock != bytes32(0));
        assertTrue(confirmationBlock != blockHash);
        assertTrue(confirmationTotalDifficulty > totalDifficulty);
        assertTrue(confirmationTimestamp != 0 && confirmationTimestamp <= block.timestamp);
    }

    function invariantPermanentHaltFreezesTheRegistry() public view {
        assertTrue(registry.halted() == handler.ghostHalted());
        if (!registry.halted()) return;
        assertEq(registry.latestBlock(), handler.haltedLatestBlock());
        assertEq(handler._candidateWord(0), handler.haltedCandidateHash());
    }
}
