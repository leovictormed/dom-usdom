// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {DOMFinalizedBurnRiscZeroVerifier} from "../../contracts/DOMFinalizedBurnRiscZeroVerifier.sol";
import {IRiscZeroVerifierV3} from "../../contracts/IRiscZeroVerifierV3.sol";
import {IDOMFinalizedBurnVerifier, USDOMProofReserve} from "../../contracts/USDOMProofReserve.sol";
import {TestBase} from "./TestBase.sol";
import {HostileToken, MockGovernance} from "./Mocks.sol";

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

contract DOMFinalizedBurnRiscZeroVerifierTest is TestBase {
    bytes32 internal constant IMAGE_ID = 0x3975a5f01dc85b6e89925913c5555ade4aefb951c65261142384fd829a70f88a;
    bytes32 internal constant STATEMENT = keccak256("finalized USDOM burn statement");
    bytes4 internal constant SELECTOR = 0x73c457ba;

    MockRiscZeroVerifierV3 internal riscZero;
    DOMFinalizedBurnRiscZeroVerifier internal adapter;

    function setUp() public {
        riscZero = new MockRiscZeroVerifierV3(SELECTOR);
        adapter = new DOMFinalizedBurnRiscZeroVerifier(IRiscZeroVerifierV3(address(riscZero)), IMAGE_ID);
    }

    function seal(bytes32 payload) internal pure returns (bytes memory) {
        return abi.encodePacked(SELECTOR, payload);
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

    function testRejectsZeroStatementShortWrongSelectorAndOversizedSeal() public {
        bytes memory proof = seal(keccak256("proof"));
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(bytes32(0), proof);
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, hex"73c457");
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, abi.encodePacked(bytes4(0x01020304), bytes32(uint256(1))));
        uint256 oversized = adapter.MAX_PROOF_BYTES() + 1;
        vm.expectRevert(DOMFinalizedBurnRiscZeroVerifier.InvalidProof.selector);
        adapter.verifyFinalizedBurn(STATEMENT, new bytes(oversized));
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
    bytes32 internal constant IMAGE_ID = 0x3975a5f01dc85b6e89925913c5555ade4aefb951c65261142384fd829a70f88a;
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
        USDOMProofReserve reserve = new USDOMProofReserve(
            USDOMProofReserve.Config({
                token: IERC20(address(token)),
                verifier: IDOMFinalizedBurnVerifier(address(adapter)),
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
        bytes memory proof = abi.encodePacked(SELECTOR, keccak256("Groth16 proof fixture"));
        bytes32 statementHash = reserve.burnStatementHash(burn);
        riscZero.expect(proof, IMAGE_ID, sha256(abi.encodePacked(statementHash)));

        reserve.queueWithdrawal(burn, proof);
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), burn.amount);
        assertEq(reserve.unreservedCollateral(), 9_000e6);
    }
}
