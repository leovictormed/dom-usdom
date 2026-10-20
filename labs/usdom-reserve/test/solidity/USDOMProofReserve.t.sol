// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IDOMFinalizedBurnVerifier, USDOMProofReserve} from "../../contracts/USDOMProofReserve.sol";
import {TestBase} from "./TestBase.sol";
import {HostileToken, MockGovernance} from "./Mocks.sol";

contract MockFinalizedBurnVerifier is IDOMFinalizedBurnVerifier {
    bytes32 public override verifierConfigHash = keccak256("DOM verifier test configuration");
    mapping(bytes32 => bool) private accepted;

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function setConfigHash(bytes32 value) external {
        verifierConfigHash = value;
    }

    function verifyFinalizedBurn(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
        if (accepted[keccak256(abi.encode(statementHash, proof))]) {
            return keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
        }
        return bytes32(0);
    }
}

contract ZeroConfigVerifier is IDOMFinalizedBurnVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        return bytes32(0);
    }

    function verifyFinalizedBurn(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    }
}

contract EmptyReturnVerifier {
    fallback() external {
        assembly ("memory-safe") {
            return(0, 0)
        }
    }
}

contract OversizedProofReturnVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        return keccak256("oversized return verifier test configuration");
    }

    fallback() external {
        bytes32 accepted = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
        assembly ("memory-safe") {
            mstore(0, accepted)
            mstore(32, 0)
            return(0, 64)
        }
    }
}

contract ReturnBombProofVerifier {
    function verifierConfigHash() external pure returns (bytes32) {
        return keccak256("return bomb verifier test configuration");
    }

    fallback() external {
        bytes32 accepted = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
        assembly ("memory-safe") {
            mstore(0, accepted)
            return(0, 0x100000)
        }
    }
}

abstract contract ProofReserveFixture is TestBase {
    uint64 internal constant INITIAL = 10_000e6;
    uint64 internal constant CAP = 100_000e6;
    uint64 internal constant FLOW = 2_000e6;
    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    bytes32 internal constant DOMAIN = keccak256("DOM proof reserve test domain");
    bytes32 internal constant ACTIVATION_SCHEDULE = keccak256("DOM proof reserve activation schedule");

    HostileToken internal token;
    MockGovernance internal governor;
    MockGovernance internal guardian;
    MockFinalizedBurnVerifier internal burnVerifier;
    USDOMProofReserve internal reserve;
    uint256 internal nonce;

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        token = new HostileToken();
        governor = new MockGovernance();
        guardian = new MockGovernance();
        burnVerifier = new MockFinalizedBurnVerifier();
        reserve = new USDOMProofReserve(config());
        token.mint(ALICE, CAP * 10);
        vm.startPrank(ALICE);
        token.approve(address(reserve), type(uint256).max);
        reserve.deposit(INITIAL, bytes32(uint256(1)), canonicalCommitment(keccak256("alice proof output commitment")));
        vm.stopPrank();
    }

    function config() internal view returns (USDOMProofReserve.Config memory) {
        return USDOMProofReserve.Config(
            IERC20(address(token)),
            IDOMFinalizedBurnVerifier(address(burnVerifier)),
            DOMAIN,
            ACTIVATION_SCHEDULE,
            address(governor),
            address(guardian),
            1 days,
            2 days,
            CAP,
            FLOW
        );
    }

    function burn(uint64 amount) internal returns (USDOMProofReserve.FinalizedBurn memory) {
        ++nonce;
        return USDOMProofReserve.FinalizedBurn(
            keccak256(abi.encode("proof burn", nonce)),
            keccak256(abi.encode("proof request", nonce)),
            BOB,
            amount,
            DOMAIN,
            1_000,
            keccak256("finalized DOM block"),
            keccak256("private USDOM state root"),
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT()),
            uint64(block.timestamp + 6 days)
        );
    }

    function proofFor(USDOMProofReserve.FinalizedBurn memory b) internal pure returns (bytes memory) {
        return abi.encode("valid zero knowledge proof fixture", b.burnId);
    }

    function approve(USDOMProofReserve.FinalizedBurn memory b, bytes memory proof) internal {
        burnVerifier.approve(reserve.burnStatementHash(b), proof);
    }

    function queued(uint64 amount) internal returns (USDOMProofReserve.FinalizedBurn memory b, bytes memory proof) {
        b = burn(amount);
        proof = proofFor(b);
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);
    }

    function govern(bytes memory data) internal {
        governor.execute(address(reserve), data);
    }
}

contract USDOMProofReserveTest is ProofReserveFixture {
    function testMainnetReleasePolicyRequiresAnInitialPause() public view {
        assertTrue(reserve.initialPauseRequired(1));
        assertFalse(reserve.initialPauseRequired(31_337));
        assertFalse(reserve.paused());
    }

    function testReserveConfigurationHashBindsTheExactDeployment() public view {
        bytes32 identityHash = keccak256(
            abi.encode(
                reserve.RESERVE_IDENTITY_TYPEHASH(),
                block.chainid,
                address(reserve),
                address(token),
                address(token).codehash,
                address(burnVerifier),
                address(burnVerifier).codehash,
                burnVerifier.verifierConfigHash(),
                DOMAIN,
                ACTIVATION_SCHEDULE
            )
        );
        bytes32 policyHash = keccak256(
            abi.encode(
                reserve.RESERVE_POLICY_TYPEHASH(),
                address(governor),
                address(governor).codehash,
                address(guardian),
                address(guardian).codehash,
                uint64(1 days),
                uint64(2 days),
                CAP,
                FLOW
            )
        );
        bytes32 expected = keccak256(abi.encode(reserve.RESERVE_CONFIG_TYPEHASH(), identityHash, policyHash));
        assertEq(reserve.reserveConfigHash(), expected);
        assertEq(reserve.PRODUCTION_RESERVE_CONFIG_HASH(), bytes32(0));
    }

    function testConstructorRejectsInvalidConfigurationTokenAndVerifierResponses() public {
        USDOMProofReserve.Config memory c = config();
        c.domDomain = bytes32(0);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        c = config();
        c.activationScheduleCommitment = bytes32(0);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        c = config();
        c.verifier = IDOMFinalizedBurnVerifier(address(token));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        token.setDecimals(18);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        new USDOMProofReserve(config());
        token.setDecimals(6);

        ZeroConfigVerifier zero = new ZeroConfigVerifier();
        c = config();
        c.verifier = IDOMFinalizedBurnVerifier(address(zero));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        EmptyReturnVerifier empty = new EmptyReturnVerifier();
        c.verifier = IDOMFinalizedBurnVerifier(address(empty));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
    }

    function testDepositRejectsInvalidDuplicateExposureInsolvencyAndLyingToken() public {
        uint256 scalarField = reserve.BN254_SCALAR_FIELD();
        vm.startPrank(ALICE);
        vm.expectRevert(USDOMProofReserve.InvalidDeposit.selector);
        reserve.deposit(0, bytes32(uint256(2)), bytes32(uint256(3)));
        vm.expectRevert(USDOMProofReserve.InvalidDeposit.selector);
        reserve.deposit(1, bytes32(uint256(2)), bytes32(0));
        vm.expectRevert(USDOMProofReserve.InvalidDeposit.selector);
        reserve.deposit(1, bytes32(uint256(2)), bytes32(scalarField));
        vm.expectRevert(USDOMProofReserve.InvalidDeposit.selector);
        reserve.deposit(1, bytes32(uint256(2)), bytes32(type(uint256).max));
        reserve.deposit(1, bytes32(uint256(22)), bytes32(scalarField - 1));
        reserve.deposit(1, bytes32(uint256(2)), bytes32(uint256(3)));
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.deposit(1, bytes32(uint256(2)), bytes32(uint256(4)));
        vm.stopPrank();

        token.confiscate(address(reserve), 1);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.Insolvent.selector);
        reserve.deposit(1, bytes32(uint256(5)), bytes32(uint256(6)));
        token.mint(address(reserve), 1);

        token.setMode(HostileToken.Mode.Lie);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.deposit(1, bytes32(uint256(7)), bytes32(uint256(8)));
        token.setMode(HostileToken.Mode.Standard);

        vm.prank(ALICE);
        reserve.deposit(CAP - INITIAL - 2, bytes32(uint256(9)), bytes32(uint256(10)));
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ExposureLimit.selector);
        reserve.deposit(1, bytes32(uint256(11)), bytes32(uint256(12)));
    }

    function testQueueRejectsInvalidFieldsWindowsCapacityAndDuplicateIds() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        b.burnId = bytes32(0);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, proof);

        uint64 currentSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        b = burn(100e6);
        b.finalityBeaconSlot = currentSlot + 1;
        proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, proof);
        b = burn(100e6);
        b.finalityBeaconSlot = currentSlot - uint64(reserve.MAX_FINALITY_AGE_SLOTS()) - 1;
        proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, proof);

        b = burn(FLOW + 1);
        proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(USDOMProofReserve.OutflowLimit.selector);
        reserve.queueWithdrawal(b, proof);

        b = burn(100e6);
        b.validUntil = 0;
        proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, proof);
        b.validUntil = uint64(block.timestamp + 7 days + 1);
        proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(USDOMProofReserve.InvalidCertificateWindow.selector);
        reserve.queueWithdrawal(b, proof);

        b = burn(100e6);
        b.validUntil = uint64(block.timestamp - 30 days);
        proof = proofFor(b);
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);
        (,, uint64 readyAt, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(b.burnId);
        assertEq(readyAt, block.timestamp + 1 days);
        assertEq(expiresAt, block.timestamp + 7 days);

        (b, proof) = queued(100e6);
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(b, proof);

        for (uint256 i; i < 4; ++i) {
            queued(FLOW);
        }
        USDOMProofReserve.FinalizedBurn memory over = burn(FLOW);
        bytes memory overProof = proofFor(over);
        approve(over, overProof);
        vm.expectRevert(USDOMProofReserve.Insolvent.selector);
        reserve.queueWithdrawal(over, overProof);
    }

    function testExecutionFailureRollsBackReservationAndCanRetry() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + 1 days);
        token.setMode(HostileToken.Mode.Lie);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalReleased(), 0);
        assertEq(reserve.totalPendingAmount(), b.amount);
        token.setMode(HostileToken.Mode.Standard);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
    }

    function testExpiredMissingAndUndercollateralizedClaimsFailClosed() public {
        (USDOMProofReserve.FinalizedBurn memory expired,) = queued(100e6);
        (,,, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(expired.burnId);
        vm.warp(expiresAt + 1);
        vm.expectRevert(USDOMProofReserve.StaleCertificate.selector);
        reserve.executeWithdrawal(expired);
        reserve.discardWithdrawal(expired.burnId);
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.discardWithdrawal(expired.burnId);

        (USDOMProofReserve.FinalizedBurn memory insolvent,) = queued(100e6);
        token.confiscate(address(reserve), 1);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(USDOMProofReserve.Insolvent.selector);
        reserve.executeWithdrawal(insolvent);
        assertFalse(reserve.paidBurns(insolvent.burnId));
        assertEq(reserve.totalPendingAmount(), insolvent.amount);
    }

    function testPruneIsBoundedAndMiddleDiscardPreservesLinks() public {
        USDOMProofReserve.FinalizedBurn memory first = burn(100e6);
        bytes memory firstProof = proofFor(first);
        approve(first, firstProof);
        reserve.queueWithdrawal(first, firstProof);

        USDOMProofReserve.FinalizedBurn memory middle = burn(100e6);
        bytes memory middleProof = proofFor(middle);
        approve(middle, middleProof);
        reserve.queueWithdrawal(middle, middleProof);

        USDOMProofReserve.FinalizedBurn memory last = burn(100e6);
        bytes memory lastProof = proofFor(last);
        approve(last, lastProof);
        reserve.queueWithdrawal(last, lastProof);

        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        reserve.pruneExpired(0);
        assertEq(reserve.pruneExpired(3), 0);
        (,,, uint64 queueExpiry,,,,) = reserve.pendingWithdrawals(middle.burnId);
        vm.warp(queueExpiry + 1);
        reserve.discardWithdrawal(middle.burnId);
        assertEq(reserve.pendingCount(), 2);
        assertEq(reserve.firstPendingBurn(), first.burnId);
        assertEq(reserve.lastPendingBurn(), last.burnId);
        assertEq(reserve.pruneExpired(1), 1);
        assertEq(reserve.firstPendingBurn(), last.burnId);
        assertEq(reserve.pruneExpired(2), 1);
        assertEq(reserve.pendingCount(), 0);
    }

    function testBatchPruneRemovesInvalidatedEntriesWithoutTouchingValidReplacement() public {
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(100e6);
        (USDOMProofReserve.FinalizedBurn memory middle,) = queued(200e6);
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(block.timestamp + 2 days);
        reserve.executeResume();
        (USDOMProofReserve.FinalizedBurn memory replacement,) = queued(300e6);

        bytes32[] memory candidates = new bytes32[](5);
        candidates[0] = replacement.burnId;
        candidates[1] = first.burnId;
        candidates[2] = keccak256("unknown proof burn");
        candidates[3] = middle.burnId;
        candidates[4] = first.burnId;
        assertEq(reserve.pruneDiscardable(candidates), 2);
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), replacement.amount);
        assertEq(reserve.firstPendingBurn(), replacement.burnId);
        assertEq(reserve.lastPendingBurn(), replacement.burnId);
        (bytes32 firstStatement,,,,,,,) = reserve.pendingWithdrawals(first.burnId);
        (bytes32 middleStatement,,,,,,,) = reserve.pendingWithdrawals(middle.burnId);
        assertEq(firstStatement, bytes32(0));
        assertEq(middleStatement, bytes32(0));

        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(replacement);

        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        reserve.pruneDiscardable(new bytes32[](0));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        reserve.pruneDiscardable(new bytes32[](257));
    }

    function testMaximumBatchPruneIsExecutableAfterEmergencyInvalidation() public {
        bytes32[] memory candidates = new bytes32[](256);
        for (uint256 i; i < candidates.length; ++i) {
            (USDOMProofReserve.FinalizedBurn memory pending,) = queued(1);
            candidates[i] = pending.burnId;
        }
        assertEq(reserve.pendingCount(), candidates.length);
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertEq(reserve.pendingCount(), 0);
        uint256 gasBefore = gasleft();
        assertEq(reserve.pruneDiscardable(candidates), candidates.length);
        uint256 pruningGas = gasBefore - gasleft();
        assertTrue(pruningGas < 20_000_000);
        for (uint256 i; i < candidates.length; ++i) {
            (bytes32 statementHash,,,,,,,) = reserve.pendingWithdrawals(candidates[i]);
            assertEq(statementHash, bytes32(0));
        }
    }

    function testResumeFailsClosedOnRepeatedPauseVerifierAndTokenPolicy() public {
        vm.expectRevert(USDOMProofReserve.NotPaused.selector);
        reserve.executeResume();
        vm.expectRevert(USDOMProofReserve.NotPaused.selector);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.Unauthorized.selector);
        reserve.scheduleResume();
        vm.expectRevert(USDOMProofReserve.NoProposal.selector);
        reserve.executeResume();
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.warp(block.timestamp + 3 days);
        vm.expectRevert(USDOMProofReserve.NoProposal.selector);
        reserve.executeResume();

        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        burnVerifier.setConfigHash(keccak256("changed while paused"));
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.executeResume();
        burnVerifier.setConfigHash(reserve.verifierConfigHash());
        token.setPolicy(true, false, 0, 0, false);
        vm.expectRevert(USDOMProofReserve.UnsafeTokenState.selector);
        reserve.executeResume();
        token.setPolicy(false, false, 0, 0, false);
        reserve.executeResume();
        assertFalse(reserve.paused());
    }

    function testOversizedVerifierReturnIsRejectedWithoutAcceptingProof() public {
        OversizedProofReturnVerifier oversized = new OversizedProofReturnVerifier();
        USDOMProofReserve.Config memory c = config();
        c.verifier = IDOMFinalizedBurnVerifier(address(oversized));
        USDOMProofReserve other = new USDOMProofReserve(c);
        token.mint(ALICE, INITIAL);
        vm.startPrank(ALICE);
        token.approve(address(other), INITIAL);
        other.deposit(INITIAL, bytes32(uint256(71)), bytes32(uint256(72)));
        vm.stopPrank();
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        other.queueWithdrawal(b, hex"01");
        assertEq(other.totalPendingAmount(), 0);
    }

    function testVerifierReturnBombIsRejectedWithoutCopyingOrAcceptingProof() public {
        ReturnBombProofVerifier returnBomb = new ReturnBombProofVerifier();
        USDOMProofReserve.Config memory c = config();
        c.verifier = IDOMFinalizedBurnVerifier(address(returnBomb));
        USDOMProofReserve other = new USDOMProofReserve(c);
        token.mint(ALICE, INITIAL);
        vm.startPrank(ALICE);
        token.approve(address(other), INITIAL);
        other.deposit(INITIAL, bytes32(uint256(73)), bytes32(uint256(74)));
        vm.stopPrank();
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        other.queueWithdrawal(b, hex"01");
        assertEq(other.totalPendingAmount(), 0);
    }

    function testFrozenAccountsFailClosedBeforeValueMoves() public {
        token.setBlocked(ALICE);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(USDOMProofReserve.FrozenTokenAccount.selector, ALICE));
        reserve.deposit(1, bytes32(uint256(81)), bytes32(uint256(82)));
        token.setBlocked(BOB);
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(abi.encodeWithSelector(USDOMProofReserve.FrozenTokenAccount.selector, BOB));
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), 0);
    }

    function testFuzzProofPayoutConservesCollateral(uint64 rawAmount) public {
        uint64 amount = rawAmount % FLOW + 1;
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(amount);
        vm.warp(block.timestamp + 1 days);
        uint256 reserveBefore = token.balanceOf(address(reserve));
        reserve.executeWithdrawal(b);
        assertEq(token.balanceOf(address(reserve)), reserveBefore - amount);
        assertEq(reserve.totalReleased(), amount);
        assertEq(reserve.outstanding(), INITIAL - amount);
    }

    function testFuzzApprovedProofCannotAuthorizeMutatedStatement(uint64 delta) public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        b.height += delta % 1_000 + 1;
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), 0);
    }

    function testFuzzDepositsPreserveAccounting(uint64 rawAmount, bytes32 salt) public {
        uint64 amount = rawAmount % (CAP - INITIAL) + 1;
        bytes32 fuzzSalt = keccak256(abi.encode("proof reserve fuzz deposit", salt));
        uint256 before = token.balanceOf(address(reserve));
        vm.prank(ALICE);
        reserve.deposit(amount, fuzzSalt, canonicalCommitment(keccak256(abi.encode("proof deposit", salt))));
        assertEq(token.balanceOf(address(reserve)), before + amount);
        assertEq(reserve.totalDeposited(), INITIAL + amount);
        assertEq(reserve.outstanding(), INITIAL + amount);
    }

    function testProductionPathIsUnavailableUntilRatifiedVerifierHashesArePinned() public {
        vm.chainId(1);
        vm.expectRevert(USDOMProofReserve.ProductionUnavailable.selector);
        new USDOMProofReserve(config());
    }

    function testConstructorRejectsEOARolesAndVerifier() public {
        USDOMProofReserve.Config memory c = config();
        c.guardian = ALICE;
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
        c = config();
        c.verifier = IDOMFinalizedBurnVerifier(ALICE);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
    }

    function testProofAuthorizedWithdrawalPaysExactlyOnce() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        assertEq(reserve.totalPendingAmount(), b.amount);
        vm.expectRevert(USDOMProofReserve.TooEarly.selector);
        reserve.executeWithdrawal(b);
        vm.warp(block.timestamp + 1 days);
        uint256 before = token.balanceOf(BOB);
        reserve.executeWithdrawal(b);
        assertEq(token.balanceOf(BOB), before + b.amount);
        assertEq(reserve.totalReleased(), b.amount);
        assertEq(reserve.totalPendingAmount(), 0);
        assertTrue(reserve.paidBurns(b.burnId));
        assertTrue(reserve.paidRequests(b.requestId));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(b);
    }

    function testInvalidProofCannotReserveCollateralOrConsumeIds() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.pendingCount(), 0);
        assertFalse(reserve.paidBurns(b.burnId));
        assertFalse(reserve.paidRequests(b.requestId));
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), b.amount);
    }

    function testProofBindsEveryPublicFieldChainAndReserve() public {
        assertEq(reserve.BURN_STATEMENT_TYPEHASH(), 0xb4a224b119278936bec16ab7cf63f13d2cc130395834d17a30335b9158062ced);
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        bytes32 original = reserve.burnStatementHash(b);

        b.recipient = ALICE;
        assertTrue(original != reserve.burnStatementHash(b));
        b.recipient = BOB;
        b.amount += 1;
        assertTrue(original != reserve.burnStatementHash(b));
        b.amount -= 1;
        b.stateRoot = keccak256("other private state");
        assertTrue(original != reserve.burnStatementHash(b));
        b.stateRoot = keccak256("private USDOM state root");
        b.finalityBeaconSlot += 1;
        assertTrue(original != reserve.burnStatementHash(b));
        b.finalityBeaconSlot -= 1;

        approve(b, proof);
        vm.chainId(block.chainid + 1);
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        reserve.queueWithdrawal(b, proof);
        vm.chainId(block.chainid - 1);

        USDOMProofReserve other = new USDOMProofReserve(config());
        token.mint(ALICE, INITIAL);
        vm.startPrank(ALICE);
        token.approve(address(other), INITIAL);
        other.deposit(INITIAL, bytes32(uint256(2)), canonicalCommitment(keccak256("other reserve output")));
        vm.stopPrank();
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        other.queueWithdrawal(b, proof);
    }

    function testFinalizedBurnStatementHashMatchesRustVector() public pure {
        bytes32 actual = keccak256(
            abi.encode(
                keccak256(
                    "FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)"
                ),
                bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111)),
                bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222)),
                address(0x3333333333333333333333333333333333333333),
                uint64(250_000),
                bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444)),
                uint64(100_360),
                bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555)),
                bytes32(uint256(0x6666666666666666666666666666666666666666666666666666666666666666)),
                uint64(16_000_010),
                uint64(1_700_100_120),
                uint256(1),
                address(0x7777777777777777777777777777777777777777),
                bytes32(uint256(0x8888888888888888888888888888888888888888888888888888888888888888))
            )
        );
        assertEq(actual, 0xd0fba5e6bd8c34e9f730bd6b198d65f16279d7c85f934eb03b4497631dd88d43);
    }

    function testBurnIntentHashBindsNativePayoutIntentOnly() public {
        assertEq(reserve.BURN_INTENT_TYPEHASH(), 0xf1d5a150f09a125f5ab99669e765334c3d22034c98b84d0f903a900320b7f446);
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes32 original = reserve.burnIntentHash(b);

        bytes32 originalBurnId = b.burnId;
        b.burnId = keccak256("other burn");
        assertTrue(original != reserve.burnIntentHash(b));
        b.burnId = originalBurnId;
        bytes32 originalRequestId = b.requestId;
        b.requestId = keccak256("other request");
        assertTrue(original != reserve.burnIntentHash(b));
        b.requestId = originalRequestId;
        b.recipient = ALICE;
        assertTrue(original != reserve.burnIntentHash(b));
        b.recipient = BOB;
        b.amount += 1;
        assertTrue(original != reserve.burnIntentHash(b));
        b.amount -= 1;
        b.domDomain = keccak256("other domain");
        assertTrue(original != reserve.burnIntentHash(b));
        b.domDomain = DOMAIN;
        b.validUntil += 1;
        assertTrue(original != reserve.burnIntentHash(b));
        b.validUntil -= 1;

        b.height += 1;
        b.blockHash = keccak256("other block");
        b.stateRoot = keccak256("other state");
        b.finalityBeaconSlot += 1;
        assertEq(original, reserve.burnIntentHash(b));

        uint256 originalChainId = block.chainid;
        vm.chainId(originalChainId + 1);
        assertTrue(original != reserve.burnIntentHash(b));
        vm.chainId(originalChainId);
        USDOMProofReserve other = new USDOMProofReserve(config());
        assertTrue(original != other.burnIntentHash(b));
    }

    function testVerifierCodeAndConfigurationAreImmutable() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        burnVerifier.setConfigHash(keccak256("changed verifier configuration"));
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.queueWithdrawal(b, proof);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.deposit(1, bytes32(uint256(99)), bytes32(uint256(100)));

        burnVerifier.setConfigHash(reserve.verifierConfigHash());
        vm.etch(address(burnVerifier), hex"00");
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.queueWithdrawal(b, proof);
    }

    function testTokenCodeIdentityIsImmutable() public {
        assertEq(reserve.ETHEREUM_USDT_CODE_HASH(), 0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55);
        assertEq(address(token).codehash, reserve.tokenCodeHash());
        vm.etch(address(token), hex"00");
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.TokenChanged.selector);
        reserve.deposit(1, bytes32(uint256(101)), bytes32(uint256(102)));
    }

    function testGuardianCodeIdentityIsImmutableAcrossValueAndResumePaths() public {
        assertEq(address(guardian).codehash, reserve.guardianCodeHash());
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.etch(address(guardian), hex"00");
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
    }

    function testGovernanceCodeIdentityIsImmutableAcrossValuePaths() public {
        assertEq(address(governor).codehash, reserve.governanceCodeHash());
        vm.etch(address(governor), hex"00");
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        reserve.deposit(1, bytes32(uint256(103)), bytes32(uint256(104)));
    }

    function testPauseRequiresContractRolesAndDelayedGovernanceResume() public {
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.Unauthorized.selector);
        reserve.pause();
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertTrue(reserve.paused());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.IsPaused.selector);
        reserve.deposit(1, bytes32(uint256(3)), bytes32(uint256(4)));
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.expectRevert(USDOMProofReserve.TooEarly.selector);
        reserve.executeResume();
        vm.warp(block.timestamp + 2 days);
        reserve.executeResume();
        assertFalse(reserve.paused());
    }

    function testEmergencyPauseInvalidatesQueueAndAllowsReviewedRequeue() public {
        (USDOMProofReserve.FinalizedBurn memory oldBurn,) = queued(100e6);
        uint64 previousEpoch = reserve.queueEpoch();
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertEq(reserve.queueEpoch(), previousEpoch + 1);
        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.pendingCount(), 0);
        assertEq(reserve.firstPendingBurn(), bytes32(0));
        assertEq(reserve.lastPendingBurn(), bytes32(0));

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertEq(reserve.queueEpoch(), previousEpoch + 1);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(block.timestamp + 2 days);
        reserve.executeResume();

        vm.expectRevert(USDOMProofReserve.StaleCertificate.selector);
        reserve.executeWithdrawal(oldBurn);

        USDOMProofReserve.FinalizedBurn memory replacement = burn(100e6);
        replacement.requestId = oldBurn.requestId;
        bytes memory replacementProof = proofFor(replacement);
        approve(replacement, replacementProof);
        reserve.queueWithdrawal(replacement, replacementProof);
        assertEq(reserve.pendingRequests(oldBurn.requestId), replacement.burnId);
        assertEq(reserve.totalPendingAmount(), replacement.amount);

        reserve.discardWithdrawal(oldBurn.burnId);
        assertEq(reserve.pendingRequests(oldBurn.requestId), replacement.burnId);
        assertEq(reserve.totalPendingAmount(), replacement.amount);
        assertEq(reserve.pendingCount(), 1);

        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(replacement);
        assertTrue(reserve.paidBurns(replacement.burnId));
        assertTrue(reserve.paidRequests(replacement.requestId));
    }

    function testExecutionFailsClosedIfVerifierChangesAfterQueue() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + 1 days);
        burnVerifier.setConfigHash(keccak256("changed after proof admission"));
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalReleased(), 0);
        assertEq(reserve.totalPendingAmount(), b.amount);

        burnVerifier.setConfigHash(reserve.verifierConfigHash());
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
    }

    function testEpochBoundPauseCannotInvalidateReviewedReplacementQueue() public {
        uint64 observedEpoch = reserve.queueEpoch();
        (USDOMProofReserve.FinalizedBurn memory oldBurn,) = queued(100e6);
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (observedEpoch)));
        assertTrue(reserve.paused());
        assertEq(reserve.queueEpoch(), observedEpoch + 1);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(block.timestamp + 2 days);
        reserve.executeResume();

        USDOMProofReserve.FinalizedBurn memory replacement = burn(100e6);
        replacement.requestId = oldBurn.requestId;
        bytes memory replacementProof = proofFor(replacement);
        approve(replacement, replacementProof);
        reserve.queueWithdrawal(replacement, replacementProof);

        bytes memory stalePause = abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (observedEpoch));
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        guardian.execute(address(reserve), stalePause);
        assertFalse(reserve.paused());
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), replacement.amount);

        uint64 currentEpoch = reserve.queueEpoch();
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.Unauthorized.selector);
        reserve.pauseQueueEpoch(currentEpoch);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (currentEpoch)));
        assertTrue(reserve.paused());
        assertEq(reserve.pendingCount(), 0);
    }

    function testExpiredProofReservationCanBeDiscardedButPaidIdsNeverClear() public {
        (USDOMProofReserve.FinalizedBurn memory expired,) = queued(100e6);
        vm.expectRevert(USDOMProofReserve.StillValid.selector);
        reserve.discardWithdrawal(expired.burnId);
        (,,, uint64 queueExpiry,,,,) = reserve.pendingWithdrawals(expired.burnId);
        vm.warp(queueExpiry + 1);
        reserve.discardWithdrawal(expired.burnId);
        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.pendingCount(), 0);

        expired.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        bytes memory proof = proofFor(expired);
        approve(expired, proof);
        reserve.queueWithdrawal(expired, proof);
        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(expired);
        approve(expired, proof);
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(expired, proof);
    }

    function testReservationsAndRateLimitCannotExceedCreditedCollateral() public {
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(FLOW);
        USDOMProofReserve.FinalizedBurn memory second = burn(FLOW);
        bytes memory secondProof = proofFor(second);
        approve(second, secondProof);
        reserve.queueWithdrawal(second, secondProof);
        assertEq(reserve.totalPendingAmount(), FLOW * 2);
        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(first);
        vm.expectRevert(USDOMProofReserve.OutflowLimit.selector);
        reserve.executeWithdrawal(second);
        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(second);
        assertEq(reserve.totalReleased(), FLOW * 2);
    }

    function testUnsafeTokenPolicyFailsClosedWithoutConsumingProof() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        token.setPolicy(true, false, 0, 0, false);
        vm.expectRevert(USDOMProofReserve.UnsafeTokenState.selector);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), 0);
        token.setPolicy(false, false, 0, 0, false);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), b.amount);
    }

    function testTimestampNarrowingAndProofSizeFailClosed() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory oversized = new bytes(reserve.MAX_PROOF_BYTES() + 1);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, oversized);

        vm.warp(type(uint64).max);
        b.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        vm.expectRevert(USDOMProofReserve.TimestampOverflow.selector);
        reserve.queueWithdrawal(b, hex"01");
    }
}
