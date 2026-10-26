// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {DOMFinalizedBurnRiscZeroVerifier} from "../../contracts/DOMFinalizedBurnRiscZeroVerifier.sol";
import {DOMCheckpointRiscZeroVerifier} from "../../contracts/DOMCheckpointRiscZeroVerifier.sol";
import {IDOMCheckpointVerifier} from "../../contracts/DOMCheckpointRegistry.sol";
import {IRiscZeroVerifierV3} from "../../contracts/IRiscZeroVerifierV3.sol";
import {
    IDOMFinalizedBurnVerifier,
    IDOMGracefulShutdownRegistry,
    USDOMProofReserve
} from "../../contracts/USDOMProofReserve.sol";
import {TestBase} from "./TestBase.sol";
import {HostileToken, MockGovernance, MockGracefulShutdownRegistry} from "./Mocks.sol";

contract MockRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
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

contract MissingSelectorVerifier {
    fallback() external {}
}

contract ReturnBombSelectorVerifier {
    fallback() external {
        assembly ("memory-safe") {
            return(0, 0x100000)
        }
    }
}

contract DirtyPaddingSelectorVerifier {
    fallback() external {
        assembly ("memory-safe") {
            mstore(0, or(shl(224, 0x73c457ba), 1))
            return(0, 32)
        }
    }
}

contract NonemptyReturnRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public constant override SELECTOR = 0x73c457ba;

    function verify(bytes calldata, bytes32, bytes32) external pure {
        assembly ("memory-safe") {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

contract ReturnBombRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public constant override SELECTOR = 0x73c457ba;

    function verify(bytes calldata, bytes32, bytes32) external pure {
        assembly ("memory-safe") {
            return(0, 0x100000)
        }
    }
}

contract GasBurningRiscZeroVerifierV3 is IRiscZeroVerifierV3 {
    bytes4 public constant override SELECTOR = 0x73c457ba;

    function verify(bytes calldata, bytes32, bytes32) external view {
        uint256 stopAt = gasleft() > 2_000 ? 2_000 : 0;
        while (gasleft() > stopAt) {}
    }
}

contract DOMFinalizedBurnRiscZeroVerifierTest is TestBase {
    bytes32 internal constant IMAGE_ID = 0x2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea;
    bytes32 internal constant STATEMENT = keccak256("finalized USDOM burn statement");
    bytes4 internal constant SELECTOR = 0x73c457ba;

    MockRiscZeroVerifierV3 internal riscZero;
    DOMFinalizedBurnRiscZeroVerifier internal adapter;

    function setUp() public {
        riscZero = new MockRiscZeroVerifierV3(SELECTOR);
        adapter = new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), IMAGE_ID);
    }

    function seal(bytes32 payload) internal pure returns (bytes memory) {
        return abi.encodePacked(SELECTOR, new bytes(7 * 32), payload);
    }

    function testConfigurationBindsChainVerifierCodeSelectorImageAndJournal() public view {
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
    }

    function testUpstreamVerifierCannotConsumeUnboundedCallerGas() public {
        GasBurningRiscZeroVerifierV3 burner = new GasBurningRiscZeroVerifierV3();
        DOMFinalizedBurnRiscZeroVerifier bounded =
            new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(burner)), IMAGE_ID);
        uint256 beforeGas = gasleft();
        assertEq(bounded.verifyFinalizedBurn(STATEMENT, seal(bytes32(uint256(1)))), bounded.PROOF_ACCEPTED());
        assertTrue(beforeGas - gasleft() < 4_800_000);
    }

    function testJournalDigestIsSha256OfExactlyThirtyTwoRawBytes() public view {
        assertEq(adapter.journalDigest(STATEMENT), sha256(abi.encodePacked(STATEMENT)));
        assertFalse(adapter.journalDigest(STATEMENT) == sha256(abi.encode(STATEMENT, uint256(32))));
    }

    function testValidSealUsesExactImageAndJournalAndReturnsReserveCapability() public {
        bytes memory proof = seal(keccak256("valid Groth16 proof payload fixture"));
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(STATEMENT)));
        assertEq(adapter.verifyFinalizedBurn(STATEMENT, proof), adapter.PROOF_ACCEPTED());
    }

    function testIdenticalReceiptInputsCannotMergeBurnAndCheckpointAdapterCapabilities() public {
        DOMCheckpointRiscZeroVerifier checkpointAdapter =
            new DOMCheckpointRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), IMAGE_ID);
        bytes memory proof = seal(keccak256("shared raw receipt fixture"));
        bytes32 digest = sha256(abi.encodePacked(STATEMENT));
        riscZero.expect(proof, IMAGE_ID, digest);

        // The raw RISC Zero tuple can be identical, but each adapter exposes a
        // distinct configuration namespace, ABI and caller capability.
        assertEq(adapter.journalDigest(STATEMENT), checkpointAdapter.journalDigest(STATEMENT));
        assertTrue(adapter.VERIFIER_CONFIG_TYPEHASH() != checkpointAdapter.VERIFIER_CONFIG_TYPEHASH());
        assertTrue(adapter.verifierConfigHash() != checkpointAdapter.verifierConfigHash());
        assertTrue(adapter.PROOF_ACCEPTED() != checkpointAdapter.PROOF_ACCEPTED());
        assertEq(adapter.verifyFinalizedBurn(STATEMENT, proof), adapter.PROOF_ACCEPTED());
        assertEq(checkpointAdapter.verifyDOMCheckpoint(STATEMENT, proof), checkpointAdapter.PROOF_ACCEPTED());

        (bool checkpointAsBurn,) = address(checkpointAdapter)
            .staticcall(abi.encodeCall(IDOMFinalizedBurnVerifier.verifyFinalizedBurn, (STATEMENT, proof)));
        (bool burnAsCheckpoint,) =
            address(adapter).staticcall(abi.encodeCall(IDOMCheckpointVerifier.verifyDOMCheckpoint, (STATEMENT, proof)));
        assertFalse(checkpointAsBurn);
        assertFalse(burnAsCheckpoint);
    }

    function testRejectsZeroStatementShortWrongSelectorAndOversizedSeal() public {
        bytes memory proof = seal(keccak256("proof"));
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(bytes32(0), proof);
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, hex"73c457");
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, abi.encodePacked(bytes4(0x01020304), bytes32(uint256(1))));
        uint256 oversized = adapter.EVM_PROOF_BYTES() + 1;
        uint256 truncated = adapter.EVM_PROOF_BYTES() - 1;
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, new bytes(oversized));
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, new bytes(truncated));
    }

    function testUnderlyingRejectionCannotBecomeAccepted() public {
        bytes memory proof = seal(keccak256("rejected proof"));
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(STATEMENT)));
        riscZero.setReject(true);
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, proof);
    }

    function testRejectsNonemptyAndBombVerifierReturnData() public {
        bytes memory proof = seal(keccak256("ABI-incompatible proof response"));
        DOMFinalizedBurnRiscZeroVerifier nonempty = new DOMFinalizedBurnRiscZeroVerifier(
            IRiscZeroVerifierV3(address(new NonemptyReturnRiscZeroVerifierV3())), IMAGE_ID
        );
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        nonempty.verifyFinalizedBurn(STATEMENT, proof);

        DOMFinalizedBurnRiscZeroVerifier bomb = new DOMFinalizedBurnRiscZeroVerifier(
            IRiscZeroVerifierV3(address(new ReturnBombRiscZeroVerifierV3())), IMAGE_ID
        );
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        bomb.verifyFinalizedBurn(STATEMENT, proof);
    }

    function testRejectsChangedChainAndChangedVerifierCode() public {
        bytes memory proof = seal(keccak256("proof"));
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(STATEMENT)));

        uint256 originalChainId = adapter.deploymentChainId();
        vm.chainId(originalChainId + 1);
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.VerifierChanged.selector);
        adapter.verifyFinalizedBurn(STATEMENT, proof);
        vm.chainId(originalChainId);

        riscZero.setSelector(0x01020304);
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.VerifierChanged.selector);
        adapter.verifyFinalizedBurn(STATEMENT, proof);
        riscZero.setSelector(SELECTOR);

        vm.etch(address(riscZero), hex"00");
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.VerifierChanged.selector);
        adapter.verifyFinalizedBurn(STATEMENT, proof);
    }

    function testConstructorRejectsMissingCodeZeroImageMissingSelectorAndWrongParameters() public {
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(0x1234)), IMAGE_ID);

        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), bytes32(0));

        MissingSelectorVerifier missing = new MissingSelectorVerifier();
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(missing)), IMAGE_ID);

        ReturnBombSelectorVerifier bomb = new ReturnBombSelectorVerifier();
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(bomb)), IMAGE_ID);

        DirtyPaddingSelectorVerifier dirty = new DirtyPaddingSelectorVerifier();
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(dirty)), IMAGE_ID);

        MockRiscZeroVerifierV3 wrong = new MockRiscZeroVerifierV3(0x01020304);
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidConfiguration.selector);
        new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(wrong)), IMAGE_ID);
    }
}

contract DOMFinalizedBurnRiscZeroReserveIntegrationTest is TestBase {
    bytes32 internal constant IMAGE_ID = 0x2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea;
    bytes4 internal constant SELECTOR = 0x73c457ba;
    bytes32 internal constant DOMAIN = keccak256("DOM RISC Zero reserve integration domain");
    bytes32 internal constant ACTIVATION = keccak256("DOM RISC Zero activation schedule");
    address internal constant ALICE = address(0xA11CE);
    address internal constant RECIPIENT = address(0xB0B);

    function testReserveQueuesOnlyTheStatementAuthenticatedByTheRiscZeroAdapter() public {
        vm.warp(1_800_000_000);
        MockRiscZeroVerifierV3 riscZero = new MockRiscZeroVerifierV3(SELECTOR);
        DOMFinalizedBurnRiscZeroVerifier adapter =
            new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), IMAGE_ID);
        HostileToken token = new HostileToken();
        MockGovernance governance = new MockGovernance();
        MockGovernance guardian = new MockGovernance();
        MockGracefulShutdownRegistry checkpointRegistry = new MockGracefulShutdownRegistry(DOMAIN, ACTIVATION);
        USDOMProofReserve reserve = new USDOMProofReserve(
            USDOMProofReserve.Config({
                token: IERC20(address(token)),
                verifier: IDOMFinalizedBurnVerifier(address(adapter)),
                checkpointRegistry: IDOMGracefulShutdownRegistry(address(checkpointRegistry)),
                domDomain: DOMAIN,
                activationScheduleCommitment: ACTIVATION,
                governance: address(governance),
                guardian: address(guardian),
                withdrawalDelay: 1 days,
                governanceDelay: 2 days,
                maxOutstanding: 100_000e6,
                outflowCapacity: 2_000e6
            })
        );

        token.mint(ALICE, 10_000e6);
        vm.startPrank(ALICE);
        token.approve(address(reserve), type(uint256).max);
        reserve.deposit(10_000e6, keccak256("deposit salt"), canonicalCommitment(keccak256("private note")));
        vm.stopPrank();

        USDOMProofReserve.FinalizedBurn memory burn = USDOMProofReserve.FinalizedBurn({
            burnId: keccak256("finalized burn"),
            requestId: keccak256("withdrawal request"),
            recipient: RECIPIENT,
            amount: 1_000e6,
            domDomain: DOMAIN,
            height: 10_000,
            blockHash: keccak256("finalized DOM block"),
            stateRoot: keccak256("private native USDOM state"),
            finalityBeaconSlot: uint64(
                (block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT()
            ),
            validUntil: uint64(block.timestamp + 6 days)
        });
        bytes memory proof = abi.encodePacked(SELECTOR, new bytes(7 * 32), keccak256("Groth16 proof fixture"));
        bytes32 statementHash = reserve.burnStatementHash(burn);
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(statementHash)));

        reserve.queueWithdrawal(burn, proof);
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), burn.amount);
        assertEq(reserve.unreservedCollateral(), 9_000e6);
    }
}
