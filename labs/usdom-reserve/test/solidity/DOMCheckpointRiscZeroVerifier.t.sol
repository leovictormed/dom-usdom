// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {DOMCheckpointRegistry, IDOMCheckpointVerifier} from "../../contracts/DOMCheckpointRegistry.sol";
import {DOMCheckpointRiscZeroVerifier} from "../../contracts/DOMCheckpointRiscZeroVerifier.sol";
import {IRiscZeroVerifierV3} from "../../contracts/IRiscZeroVerifierV3.sol";
import {TestBase} from "./TestBase.sol";
import {MockGovernance} from "./Mocks.sol";

contract MockCheckpointRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public override SELECTOR;
    bytes32 private expectedImageId;
    bytes32 private expectedJournalDigest;
    bytes32 private expectedSealHash;
    bool private reject;

    error VerificationFailed();

    constructor(bytes4 selector_) {
        SELECTOR = selector_;
    }

    function setSelector(bytes4 value) external {
        SELECTOR = value;
    }

    function expect(bytes calldata seal, bytes32 imageId, bytes32 journalDigest_) external {
        expectedSealHash = keccak256(seal);
        expectedImageId = imageId;
        expectedJournalDigest = journalDigest_;
    }

    function setReject(bool value) external {
        reject = value;
    }

    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest_) external view {
        if (
            reject || keccak256(seal) != expectedSealHash || imageId != expectedImageId
                || journalDigest_ != expectedJournalDigest
        ) revert VerificationFailed();
    }
}

contract MissingCheckpointRiscZeroSelector {
    fallback() external {}
}

contract ReturnBombCheckpointRiscZeroSelector {
    fallback() external {
        assembly ("memory-safe") {
            return(0, 0x100000)
        }
    }
}

contract DirtyPaddingCheckpointRiscZeroSelector {
    fallback() external {
        assembly ("memory-safe") {
            mstore(0, or(shl(224, 0x73c457ba), 1))
            return(0, 32)
        }
    }
}

contract NonemptyReturnCheckpointRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public constant override SELECTOR = 0x73c457ba;

    function verify(bytes calldata, bytes32, bytes32) external pure {
        assembly ("memory-safe") {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

contract ReturnBombCheckpointRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public constant override SELECTOR = 0x73c457ba;

    function verify(bytes calldata, bytes32, bytes32) external pure {
        assembly ("memory-safe") {
            return(0, 0x100000)
        }
    }
}

contract GasBurningCheckpointRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public constant override SELECTOR = 0x73c457ba;

    function verify(bytes calldata, bytes32, bytes32) external view {
        uint256 stopAt = gasleft() > 2_000 ? 2_000 : 0;
        while (gasleft() > stopAt) {}
    }
}

contract DOMCheckpointRiscZeroVerifierTest is TestBase {
    bytes32 internal constant IMAGE_ID = keccak256("DOM checkpoint RISC Zero guest ImageID");
    bytes32 internal constant STATEMENT = keccak256("DOM checkpoint statement");
    bytes4 internal constant SELECTOR = 0x73c457ba;

    MockCheckpointRiscZeroVerifierV3 internal riscZero;
    DOMCheckpointRiscZeroVerifier internal adapter;

    function setUp() public {
        riscZero = new MockCheckpointRiscZeroVerifierV3(SELECTOR);
        adapter = new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), IMAGE_ID);
    }

    function seal(bytes32 payload) internal pure returns (bytes memory) {
        return abi.encodePacked(SELECTOR, new bytes(7 * 32), payload);
    }

    function testConfigurationBindsChainVerifierCodeSelectorImageJournalAndCapability() public view {
        bytes32 expected = keccak256(
            abi.encode(
                adapter.VERIFIER_CONFIG_TYPEHASH(),
                block.chainid,
                address(riscZero),
                address(riscZero).codehash,
                SELECTOR,
                IMAGE_ID,
                adapter.JOURNAL_SCHEMA_HASH(),
                adapter.PROOF_ACCEPTED()
            )
        );
        assertEq(adapter.verifierConfigHash(), expected);
        assertEq(adapter.riscZeroVerifierCodeHash(), address(riscZero).codehash);
        assertEq(adapter.imageId(), IMAGE_ID);
        assertEq(adapter.deploymentChainId(), block.chainid);
        assertEq(uint256(uint32(adapter.verifierSelector())), uint256(uint32(SELECTOR)));
        assertEq(adapter.RISC_ZERO_VERIFIER_GAS_LIMIT(), 4_500_000);
        assertEq(adapter.PROOF_ACCEPTED(), keccak256("DOM_CHECKPOINT_PROOF_V3"));
    }

    function testUpstreamVerifierCannotConsumeUnboundedRegistryGas() public {
        GasBurningCheckpointRiscZeroVerifierV3 burner = new GasBurningCheckpointRiscZeroVerifierV3();
        DOMCheckpointRiscZeroVerifier bounded =
            new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(burner)), IMAGE_ID);
        uint256 beforeGas = gasleft();
        assertEq(bounded.verifyDOMCheckpoint(STATEMENT, seal(bytes32(uint256(1)))), bounded.PROOF_ACCEPTED());
        assertTrue(beforeGas - gasleft() < 4_800_000);
    }

    function testJavascriptConfigurationVectorMatchesSolidityAdapterSchema() public view {
        bytes32 expected = 0x757c4b08b41ede4e7f85f3d244d612b31ef53d90c84f1d2acfac42885ad2cd43;
        bytes32 actual = keccak256(
            abi.encode(
                adapter.VERIFIER_CONFIG_TYPEHASH(),
                uint256(1),
                address(0x10),
                bytes32(uint256(0x1010101010101010101010101010101010101010101010101010101010101010)),
                SELECTOR,
                bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)),
                adapter.JOURNAL_SCHEMA_HASH(),
                adapter.PROOF_ACCEPTED()
            )
        );
        assertEq(actual, expected);
    }

    function testValidSealUsesExactImageAndRawStatementJournal() public {
        bytes memory proof = seal(keccak256("valid checkpoint proof payload"));
        bytes32 expectedDigest = sha256(abi.encodePacked(STATEMENT));
        riscZero.expect(proof, IMAGE_ID, expectedDigest);
        assertEq(adapter.journalDigest(STATEMENT), expectedDigest);
        assertEq(adapter.verifyDOMCheckpoint(STATEMENT, proof), adapter.PROOF_ACCEPTED());
    }

    function testRejectsZeroStatementShortWrongSelectorAndOversizedSeal() public {
        bytes memory proof = seal(keccak256("checkpoint proof"));
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyDOMCheckpoint(bytes32(0), proof);
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, hex"73c457");
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, abi.encodePacked(bytes4(0x01020304), bytes32(uint256(1))));
        uint256 oversized = adapter.EVM_PROOF_BYTES() + 1;
        uint256 truncated = adapter.EVM_PROOF_BYTES() - 1;
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, new bytes(oversized));
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, new bytes(truncated));
    }

    function testUnderlyingRejectionCannotBecomeAccepted() public {
        bytes memory proof = seal(keccak256("rejected checkpoint proof"));
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(STATEMENT)));
        riscZero.setReject(true);
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, proof);
    }

    function testRejectsNonemptyAndBombVerifierReturnData() public {
        bytes memory proof = seal(keccak256("ABI-incompatible checkpoint response"));
        DOMCheckpointRiscZeroVerifier nonempty = new DOMCheckpointRiscZeroVerifier(
            IRiscZeroVerifierV3(address(new NonemptyReturnCheckpointRiscZeroVerifierV3())), IMAGE_ID
        );
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        nonempty.verifyDOMCheckpoint(STATEMENT, proof);

        DOMCheckpointRiscZeroVerifier bomb = new DOMCheckpointRiscZeroVerifier(
            IRiscZeroVerifierV3(address(new ReturnBombCheckpointRiscZeroVerifierV3())), IMAGE_ID
        );
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidProof.selector);
        bomb.verifyDOMCheckpoint(STATEMENT, proof);
    }

    function testRejectsChangedChainSelectorAndVerifierCode() public {
        bytes memory proof = seal(keccak256("checkpoint proof"));
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(STATEMENT)));

        uint256 originalChainId = adapter.deploymentChainId();
        vm.chainId(originalChainId + 1);
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.VerifierChanged.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, proof);
        vm.chainId(originalChainId);

        riscZero.setSelector(0x01020304);
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.VerifierChanged.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, proof);
        riscZero.setSelector(SELECTOR);

        vm.etch(address(riscZero), hex"00");
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.VerifierChanged.selector);
        adapter.verifyDOMCheckpoint(STATEMENT, proof);
    }

    function testConstructorRejectsMissingCodeZeroImageMissingSelectorReturnBombAndWrongSelector() public {
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(0x1234)), IMAGE_ID);

        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), bytes32(0));

        MissingCheckpointRiscZeroSelector missing = new MissingCheckpointRiscZeroSelector();
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(missing)), IMAGE_ID);

        ReturnBombCheckpointRiscZeroSelector bomb = new ReturnBombCheckpointRiscZeroSelector();
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(bomb)), IMAGE_ID);

        DirtyPaddingCheckpointRiscZeroSelector dirty = new DirtyPaddingCheckpointRiscZeroSelector();
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(dirty)), IMAGE_ID);

        MockCheckpointRiscZeroVerifierV3 wrong = new MockCheckpointRiscZeroVerifierV3(0x01020304);
        vm.expectRevert(DOMCheckpointRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(wrong)), IMAGE_ID);
    }
}

contract DOMCheckpointRiscZeroRegistryIntegrationTest is TestBase {
    bytes32 internal constant IMAGE_ID = keccak256("DOM checkpoint RISC Zero guest ImageID");
    bytes4 internal constant SELECTOR = 0x73c457ba;
    uint64 internal constant INITIAL_HEIGHT = 100_000;
    uint32 internal constant INTERVAL = 360;
    uint32 internal constant CONFIRMATION_DEPTH = 30;

    function testRegistryAcceptsOnlyTheStatementAuthenticatedByTheRiscZeroAdapter() public {
        vm.warp(1_800_000_000);
        MockCheckpointRiscZeroVerifierV3 riscZero = new MockCheckpointRiscZeroVerifierV3(SELECTOR);
        DOMCheckpointRiscZeroVerifier adapter =
            new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), IMAGE_ID);
        MockGovernance guardian = new MockGovernance();
        DOMCheckpointRegistry registry = new DOMCheckpointRegistry(
            DOMCheckpointRegistry.Config({
                bridgeDomain: keccak256("DOM checkpoint RISC Zero domain"),
                domNetworkMagic: 0xA1B2C3D4,
                domChainId: keccak256("DOM checkpoint RISC Zero chain"),
                firstV4Height: INITIAL_HEIGHT + 1,
                activationEmptyStateRoot: keccak256("activation empty state"),
                activationScheduleCommitment: keccak256("activation schedule"),
                checkpointInterval: INTERVAL,
                confirmationDepth: CONFIRMATION_DEPTH,
                challengePeriod: 2 days,
                verifier: IDOMCheckpointVerifier(address(adapter)),
                guardian: address(guardian),
                initialHeight: INITIAL_HEIGHT,
                initialBlock: keccak256("initial block"),
                initialStateRoot: keccak256("activation empty state"),
                initialContextHash: keccak256("initial continuation context"),
                initialTotalDifficulty: 1_000_000
            })
        );
        DOMCheckpointRegistry.CheckpointInput memory checkpoint = DOMCheckpointRegistry.CheckpointInput({
            previousHeight: INITIAL_HEIGHT,
            previousBlock: keccak256("initial block"),
            previousStateRoot: keccak256("activation empty state"),
            previousContextHash: keccak256("initial continuation context"),
            previousTotalDifficulty: 1_000_000,
            height: INITIAL_HEIGHT + INTERVAL,
            blockHash: keccak256("proved checkpoint block"),
            stateRoot: keccak256("proved checkpoint state"),
            contextHash: keccak256("proved checkpoint continuation context"),
            totalDifficulty: 1_000_360,
            totalIssued: 0,
            totalBurned: 0,
            issuanceClosed: false,
            confirmationHeight: INITIAL_HEIGHT + INTERVAL + CONFIRMATION_DEPTH,
            confirmationBlock: keccak256("proved confirmation block"),
            confirmationTotalDifficulty: 1_000_390,
            confirmationTimestamp: uint64(block.timestamp - 1)
        });
        bytes memory proof =
            abi.encodePacked(SELECTOR, new bytes(7 * 32), keccak256("checkpoint Groth16 proof fixture"));
        bytes32 statementHash = registry.checkpointStatementHash(checkpoint);
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(statementHash)));

        registry.submitCheckpointCandidate(checkpoint, proof);
        (bool ok, bytes memory candidateResult) = address(registry).staticcall(abi.encodeWithSignature("candidate()"));
        assertTrue(ok);
        assertEq(candidateResult.length, 13 * 32);
        bytes32 selected;
        assembly ("memory-safe") {
            selected := mload(add(candidateResult, 32))
        }
        assertEq(selected, statementHash);
        assertEq(registry.verifierConfigHash(), adapter.verifierConfigHash());
    }
}
