// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {TestBase} from "./TestBase.sol";
import {HostileToken, MockGovernance} from "./Mocks.sol";

abstract contract ReserveFixture is TestBase {
    uint64 internal constant INITIAL = 10_000e6;
    uint64 internal constant CAP = 100_000e6;
    uint64 internal constant FLOW = 2_000e6;
    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant GUARDIAN = address(0x600D);
    address internal constant ATTACKER = address(0xBAD);
    bytes32 internal constant DOMAIN = keccak256("DOM private notes test domain");
    HostileToken internal token;
    MockGovernance internal governor;
    USDOMReserve internal reserve;
    uint256[4] internal keys;
    address[] internal signers;
    uint256 internal nonce;

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        token = new HostileToken();
        governor = new MockGovernance();
        vm.etch(GUARDIAN, hex"00");
        signers = new address[](4);
        for (uint256 i; i < 4; ++i) {
            keys[i] = i + 101;
            signers[i] = vm.addr(keys[i]);
        }
        for (uint256 i; i < 4; ++i) {
            for (uint256 j = i + 1; j < 4; ++j) {
                if (signers[j] < signers[i]) {
                    (signers[i], signers[j]) = (signers[j], signers[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
        reserve = new USDOMReserve(config(), signers, 3);
        token.mint(ALICE, CAP * 10);
        vm.startPrank(ALICE);
        token.approve(address(reserve), type(uint256).max);
        reserve.deposit(INITIAL, bytes32(uint256(1)), canonicalCommitment(keccak256("alice output commitment")));
        vm.stopPrank();
    }

    function config() internal view returns (USDOMReserve.Config memory) {
        return
            USDOMReserve.Config(IERC20(address(token)), DOMAIN, address(governor), GUARDIAN, 1 days, 2 days, CAP, FLOW);
    }

    function burn(uint64 amount) internal returns (USDOMReserve.Burn memory) {
        ++nonce;
        return USDOMReserve.Burn(
            keccak256(abi.encode("burn", nonce)),
            keccak256(abi.encode("request", nonce)),
            BOB,
            amount,
            DOMAIN,
            100,
            keccak256("finalized block fixture"),
            reserve.currentEpoch(),
            uint64(block.timestamp + 6 days)
        );
    }

    function signatures(USDOMReserve.Burn memory b) internal view returns (bytes[] memory result) {
        result = signDigest(reserve.burnDigest(b));
    }

    function signDigest(bytes32 digest) internal view returns (bytes[] memory result) {
        result = new bytes[](3);
        for (uint256 i; i < 3; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            result[i] = abi.encodePacked(r, s, v);
        }
    }

    function queued(uint64 amount) internal returns (USDOMReserve.Burn memory b) {
        b = burn(amount);
        reserve.queueWithdrawal(b, signatures(b));
    }

    function mature() internal {
        vm.warp(block.timestamp + 1 days);
    }

    function govern(bytes memory data) internal {
        governor.execute(address(reserve), data);
    }

    function assertUnpaid(USDOMReserve.Burn memory b) internal view {
        assertFalse(reserve.paidBurns(b.burnId));
        assertFalse(reserve.paidRequests(b.requestId));
    }

    function clone(USDOMReserve.Burn memory b) internal pure returns (USDOMReserve.Burn memory) {
        return abi.decode(abi.encode(b), (USDOMReserve.Burn));
    }
}

contract USDOMReserveTest is ReserveFixture {
    function testDepositIdsBindFunderContractAndChain() public {
        bytes32 salt = keccak256("same salt");
        bytes32 receivingCommitment = canonicalCommitment(keccak256("receive"));
        bytes32 a = reserve.depositId(ALICE, salt);
        assertTrue(a != reserve.depositId(BOB, salt));
        vm.prank(ALICE);
        assertEq(reserve.deposit(100, salt, receivingCommitment), a);
        (address funder, uint64 amount, bytes32 commitment) = reserve.deposits(a);
        assertEq(funder, ALICE);
        assertEq(amount, 100);
        assertEq(commitment, receivingCommitment);
        vm.prank(ALICE);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.deposit(100, salt, canonicalCommitment(keccak256("other output")));
        vm.chainId(block.chainid + 1);
        assertTrue(a != reserve.depositId(ALICE, salt));
        USDOMReserve other = new USDOMReserve(config(), signers, 3);
        assertTrue(reserve.depositId(ALICE, salt) != other.depositId(ALICE, salt));
    }

    function testRejectZeroDepositOrCommitment() public {
        vm.startPrank(ALICE);
        vm.expectRevert();
        reserve.deposit(0, bytes32(0), bytes32(uint256(1)));
        vm.expectRevert();
        reserve.deposit(1, bytes32(0), bytes32(0));
        vm.stopPrank();
        assertEq(reserve.totalDeposited(), INITIAL);
    }

    function testExposureLimitAndDonationsDoNotMintCredit() public {
        token.mint(address(reserve), 123e6);
        assertEq(reserve.outstanding(), INITIAL);
        vm.startPrank(ALICE);
        reserve.deposit(CAP - INITIAL, bytes32(uint256(2)), bytes32(uint256(2)));
        vm.expectRevert(USDOMReserve.ExposureLimit.selector);
        reserve.deposit(1, bytes32(uint256(3)), bytes32(uint256(3)));
        vm.stopPrank();
        assertEq(reserve.outstanding(), CAP);
        assertEq(token.balanceOf(address(reserve)), CAP + 123e6);
    }

    function testExactDelayAndPermissionlessRelayerPayOnlySignedRecipient() public {
        USDOMReserve.Burn memory b = queued(100e6);
        vm.warp(block.timestamp + 1 days - 1);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeWithdrawal(b);
        vm.warp(block.timestamp + 1);
        vm.prank(ATTACKER);
        reserve.executeWithdrawal(b);
        assertEq(token.balanceOf(BOB), b.amount);
        assertEq(token.balanceOf(ATTACKER), 0);
        assertEq(reserve.outstanding(), INITIAL - b.amount);
        assertEq(reserve.totalReleased(), b.amount);
        assertTrue(reserve.paidBurns(b.burnId));
        assertTrue(reserve.paidRequests(b.requestId));
        assertEq(reserve.pendingRequests(b.requestId), bytes32(0));
    }

    function testEverySignedFieldIsBound() public {
        USDOMReserve.Burn memory original = burn(100e6);
        bytes[] memory sigs = signatures(original);
        for (uint256 i; i < 9; ++i) {
            USDOMReserve.Burn memory b = clone(original);
            if (i == 0) b.burnId = keccak256("substitute burn");
            if (i == 1) b.requestId = keccak256("substitute request");
            if (i == 2) b.recipient = ATTACKER;
            if (i == 3) b.amount += 1;
            if (i == 4) b.domDomain = keccak256("substitute domain");
            if (i == 5) b.height += 1;
            if (i == 6) b.blockHash = keccak256("substitute block");
            if (i == 7) b.epoch += 1;
            if (i == 8) b.validUntil -= 1;
            vm.expectRevert();
            reserve.queueWithdrawal(b, sigs);
        }
        reserve.queueWithdrawal(original, sigs);
    }

    function testSignaturesCannotReplayAcrossContractOrChain() public {
        USDOMReserve.Burn memory b = burn(1);
        bytes[] memory sigs = signatures(b);
        USDOMReserve other = new USDOMReserve(config(), signers, 3);
        vm.startPrank(ALICE);
        token.approve(address(other), INITIAL);
        other.deposit(INITIAL, bytes32(uint256(1)), bytes32(uint256(1)));
        vm.stopPrank();
        vm.expectRevert();
        other.queueWithdrawal(b, sigs);
        vm.chainId(block.chainid + 1);
        vm.expectRevert();
        reserve.queueWithdrawal(b, sigs);
    }

    function testQuorumMissingDuplicateUnsortedAndOutsiderFail() public {
        USDOMReserve.Burn memory b = burn(100e6);
        bytes[] memory sigs = signatures(b);
        bytes[] memory shortSigs = new bytes[](2);
        shortSigs[0] = sigs[0];
        shortSigs[1] = sigs[1];
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, shortSigs);
        bytes[] memory manySigs = new bytes[](4);
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, manySigs);
        sigs[1] = sigs[0];
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, sigs);
        sigs = signatures(b);
        (sigs[0], sigs[1]) = (sigs[1], sigs[0]);
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, sigs);
        sigs = signatures(b);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(999, reserve.burnDigest(b));
        sigs[0] = abi.encodePacked(r, s, v);
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, sigs);
    }

    function testMalformedHighSAndInvalidVSignaturesFail() public {
        USDOMReserve.Burn memory b = burn(1);
        bytes[] memory sigs = signatures(b);
        sigs[0] = hex"01";
        vm.expectRevert();
        reserve.queueWithdrawal(b, sigs);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[0], reserve.burnDigest(b));
        uint256 curveOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        sigs[0] = abi.encodePacked(r, bytes32(curveOrder - uint256(s)), uint8(v == 27 ? 28 : 27));
        vm.expectRevert();
        reserve.queueWithdrawal(b, sigs);
        sigs[0] = abi.encodePacked(r, s, uint8(0));
        vm.expectRevert();
        reserve.queueWithdrawal(b, sigs);
        sigs[0] = new bytes(65);
        vm.expectRevert();
        reserve.queueWithdrawal(b, sigs);
    }

    function testBothIdsUniqueWhilePendingAndAfterPayment() public {
        USDOMReserve.Burn memory b = queued(1);
        bytes[] memory sigs = signatures(b);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(b, sigs);
        USDOMReserve.Burn memory other = clone(b);
        other.burnId = keccak256("another burn");
        sigs = signatures(other);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(other, sigs);
        other = clone(b);
        other.requestId = keccak256("another request");
        sigs = signatures(other);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(other, sigs);
        mature();
        reserve.executeWithdrawal(b);
        sigs = signatures(b);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(b, sigs);
        sigs = signatures(other);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(other, sigs);
        other = clone(b);
        other.burnId = keccak256("another burn");
        sigs = signatures(other);
        vm.expectRevert(USDOMReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(other, sigs);
        vm.expectRevert(USDOMReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(b);
        vm.expectRevert(USDOMReserve.PendingMismatch.selector);
        reserve.discardWithdrawal(b.burnId);
    }

    function testInvalidBurnFieldsAndAmounts() public {
        USDOMReserve.Burn memory original = burn(1);
        for (uint256 i; i < 11; ++i) {
            USDOMReserve.Burn memory b = clone(original);
            if (i == 0) b.burnId = bytes32(0);
            if (i == 1) b.requestId = bytes32(0);
            if (i == 2) b.recipient = address(0);
            if (i == 3) b.recipient = address(reserve);
            if (i == 4) b.recipient = address(token);
            if (i == 5) b.amount = 0;
            if (i == 6) b.domDomain = bytes32(0);
            if (i == 7) b.height = 0;
            if (i == 8) b.blockHash = bytes32(0);
            if (i == 9) b.amount = INITIAL + 1;
            if (i == 10) b.amount = FLOW + 1;
            bytes[] memory sigs = signatures(b);
            vm.expectRevert();
            reserve.queueWithdrawal(b, sigs);
        }
    }

    function testCertificateWindowsAndExactExpiry() public {
        USDOMReserve.Burn memory b = burn(1);
        b.validUntil = uint64(block.timestamp + 1 days + 1 hours - 1);
        bytes[] memory sigs = signatures(b);
        vm.expectRevert(USDOMReserve.InvalidCertificateWindow.selector);
        reserve.queueWithdrawal(b, sigs);
        b.validUntil = uint64(block.timestamp + 7 days + 1);
        sigs = signatures(b);
        vm.expectRevert(USDOMReserve.InvalidCertificateWindow.selector);
        reserve.queueWithdrawal(b, sigs);
        b.validUntil = uint64(block.timestamp + 1 days + 1 hours);
        reserve.queueWithdrawal(b, signatures(b));
        USDOMReserve.Burn memory c = burn(1);
        c.validUntil = uint64(block.timestamp + 7 days);
        reserve.queueWithdrawal(c, signatures(c));
        vm.warp(b.validUntil);
        reserve.executeWithdrawal(b);
        vm.warp(c.validUntil);
        reserve.executeWithdrawal(c);
    }

    function testExpiredCertificateDiscardAndFreshAttestationRestartDelay() public {
        USDOMReserve.Burn memory b = queued(1);
        vm.expectRevert(USDOMReserve.StillValid.selector);
        reserve.discardWithdrawal(b.burnId);
        vm.warp(b.validUntil + 1);
        vm.expectRevert(USDOMReserve.StaleCertificate.selector);
        reserve.executeWithdrawal(b);
        reserve.discardWithdrawal(b.burnId);
        assertEq(reserve.pendingRequests(b.requestId), bytes32(0));
        assertUnpaid(b);
        b.validUntil = uint64(block.timestamp + 6 days);
        reserve.queueWithdrawal(b, signatures(b));
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeWithdrawal(b);
        mature();
        reserve.executeWithdrawal(b);
    }

    function testQueuedCertificateCannotChangeRecipientAmountOrDeadline() public {
        USDOMReserve.Burn memory b = queued(1);
        mature();
        USDOMReserve.Burn memory altered = clone(b);
        altered.recipient = ATTACKER;
        vm.expectRevert(USDOMReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(altered);
        altered = clone(b);
        altered.amount = 2;
        vm.expectRevert(USDOMReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(altered);
        altered = clone(b);
        altered.validUntil += 1;
        vm.expectRevert(USDOMReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(altered);
        reserve.executeWithdrawal(b);
    }

    function testTokenBucketRefillAndBoundaryDoNotResetCapacity() public {
        USDOMReserve.Burn memory b = queued(FLOW);
        USDOMReserve.Burn memory c = queued(FLOW / 2);
        mature();
        reserve.executeWithdrawal(b);
        assertEq(reserve.availableOutflow(), 0);
        vm.expectRevert(USDOMReserve.OutflowLimit.selector);
        reserve.executeWithdrawal(c);
        vm.warp(block.timestamp + 12 hours - 1);
        vm.expectRevert(USDOMReserve.OutflowLimit.selector);
        reserve.executeWithdrawal(c);
        vm.warp(block.timestamp + 1);
        assertEq(reserve.availableOutflow(), FLOW / 2);
        reserve.executeWithdrawal(c);
        assertEq(reserve.availableOutflow(), 0);
        vm.warp(block.timestamp + 100 days);
        assertEq(reserve.availableOutflow(), FLOW);
    }

    function testOversubscribedQueueNeverPaysBeyondCreditedDepositsEvenWithDonations() public {
        // Use a small reserve and donation, to distinguish credited collateral from balance.
        USDOMReserve small = new USDOMReserve(config(), signers, 3);
        vm.startPrank(ALICE);
        token.approve(address(small), 10);
        small.deposit(10, bytes32(uint256(10)), bytes32(uint256(10)));
        vm.stopPrank();
        token.mint(address(small), 1000);
        reserve = small;
        USDOMReserve.Burn memory b = queued(10);
        USDOMReserve.Burn memory c = burn(10);
        bytes[] memory sigs = signatures(c);
        vm.expectRevert(USDOMReserve.Insolvent.selector);
        reserve.queueWithdrawal(c, sigs);
        mature();
        reserve.executeWithdrawal(b);
        assertEq(reserve.totalReleased(), 10);
        assertEq(token.balanceOf(address(reserve)), 1000);
    }

    function testUnauthorizedGovernanceAndGuardianCallsFail() public {
        vm.startPrank(ATTACKER);
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.pauseOperational();
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.scheduleResume();
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.proposeNotaries(signers, 3);
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.cancelNotariesProposal();
        vm.stopPrank();
        vm.prank(GUARDIAN);
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.proposeNotaries(signers, 3);
        vm.prank(GUARDIAN);
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.scheduleResume();
        vm.expectRevert(USDOMReserve.NotPaused.selector);
        reserve.executeResume();
        vm.expectRevert(USDOMReserve.NotPaused.selector);
        govern(abi.encodeCall(reserve.scheduleResume, ()));
    }

    function testPauseBlocksAllValuePathsAndResumeHasNonBypassableDelay() public {
        USDOMReserve.Burn memory b = queued(1);
        USDOMReserve.Burn memory c = burn(1);
        bytes[] memory sigs = signatures(c);
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        vm.prank(ALICE);
        vm.expectRevert(USDOMReserve.IsPaused.selector);
        reserve.deposit(1, bytes32(uint256(2)), bytes32(uint256(2)));
        vm.expectRevert(USDOMReserve.IsPaused.selector);
        reserve.queueWithdrawal(c, sigs);
        mature();
        vm.expectRevert(USDOMReserve.IsPaused.selector);
        reserve.executeWithdrawal(b);
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeResume();
        govern(abi.encodeCall(reserve.scheduleResume, ()));
        vm.warp(block.timestamp + 2 days - 1);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeResume();
        vm.warp(block.timestamp + 1);
        vm.prank(ATTACKER);
        reserve.executeResume();
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paused());
    }

    function testRepeatedPauseCancelsScheduledResume() public {
        govern(abi.encodeCall(reserve.pauseOperational, ()));
        govern(abi.encodeCall(reserve.scheduleResume, ()));
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        vm.warp(block.timestamp + 3 days);
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeResume();
        assertTrue(reserve.paused());
    }

    function testRotationRevokesQueuedAndUnqueuedCertificates() public {
        USDOMReserve.Burn memory b = queued(1);
        USDOMReserve.Burn memory c = burn(1);
        bytes[] memory oldSigs = signatures(c);
        govern(abi.encodeCall(reserve.proposeNotaries, (signers, 3)));
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeNotaries(signers, 3);
        vm.warp(block.timestamp + 2 days);
        vm.prank(ATTACKER);
        reserve.executeNotaries(signers, 3);
        assertEq(reserve.currentEpoch(), 2);
        vm.expectRevert(USDOMReserve.StaleCertificate.selector);
        reserve.executeWithdrawal(b);
        vm.expectRevert(USDOMReserve.StaleCertificate.selector);
        reserve.queueWithdrawal(c, oldSigs);
        reserve.discardWithdrawal(b.burnId);
        assertUnpaid(b);
        b.epoch = 2;
        b.validUntil = uint64(block.timestamp + 6 days);
        reserve.queueWithdrawal(b, signatures(b));
        mature();
        reserve.executeWithdrawal(b);
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeNotaries(signers, 3);
    }

    function testRotationCannotSubstituteProposalAndGuardianCanCancelIt() public {
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeNotaries(signers, 3);
        govern(abi.encodeCall(reserve.proposeNotaries, (signers, 3)));
        vm.warp(block.timestamp + 2 days);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        reserve.executeNotaries(signers, 4);
        vm.prank(GUARDIAN);
        reserve.cancelNotariesProposal();
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeNotaries(signers, 3);
        vm.prank(GUARDIAN);
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.cancelNotariesProposal();
        govern(abi.encodeCall(reserve.proposeNotaries, (signers, 3)));
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeNotaries(signers, 3);
    }

    function testNewNotarySetRemovesOldKeys() public {
        address[] memory next = new address[](3);
        uint256[3] memory nextKeys = [uint256(1001), uint256(1002), uint256(1003)];
        for (uint256 i; i < 3; ++i) {
            next[i] = vm.addr(nextKeys[i]);
        }
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (next[j] < next[i]) {
                    (next[i], next[j]) = (next[j], next[i]);
                    (nextKeys[i], nextKeys[j]) = (nextKeys[j], nextKeys[i]);
                }
            }
        }
        govern(abi.encodeCall(reserve.proposeNotaries, (next, 3)));
        vm.warp(block.timestamp + 2 days);
        reserve.executeNotaries(next, 3);
        USDOMReserve.Burn memory b = burn(1);
        bytes[] memory sigs = signatures(b);
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, sigs);
        for (uint256 i; i < 3; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(nextKeys[i], reserve.burnDigest(b));
            sigs[i] = abi.encodePacked(r, s, v);
        }
        reserve.queueWithdrawal(b, sigs);
        mature();
        reserve.executeWithdrawal(b);
    }

    function testPauseAndRotateRevokesCertificatesBeforeResume() public {
        USDOMReserve.Burn memory b = queued(FLOW);
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        govern(abi.encodeCall(reserve.proposeNotaries, (signers, 3)));
        vm.warp(block.timestamp + 2 days);
        reserve.executeNotaries(signers, 3);
        govern(abi.encodeCall(reserve.scheduleResume, ()));
        vm.warp(block.timestamp + 2 days);
        reserve.executeResume();
        vm.expectRevert(USDOMReserve.StaleCertificate.selector);
        reserve.executeWithdrawal(b);
        assertEq(reserve.totalReleased(), 0);
    }

    function testNoReturnUSDTStyleTokenWorksInBothDirections() public {
        token.setMode(HostileToken.Mode.NoReturn);
        vm.prank(ALICE);
        reserve.deposit(100, bytes32(uint256(2)), bytes32(uint256(2)));
        USDOMReserve.Burn memory b = queued(100);
        mature();
        reserve.executeWithdrawal(b);
        assertEq(reserve.outstanding(), INITIAL);
        assertEq(token.balanceOf(BOB), 100);
    }

    function testFalseMalformedLyingAndFeeTokensCannotCreateDepositCredit() public {
        for (uint256 i = 2; i <= 6; ++i) {
            token.setMode(HostileToken.Mode(i));
            bytes32 salt = bytes32(i);
            bytes32 id = reserve.depositId(ALICE, salt);
            uint256 aliceBefore = token.balanceOf(ALICE);
            vm.prank(ALICE);
            vm.expectRevert();
            reserve.deposit(100, salt, bytes32(uint256(1)));
            (, uint64 amount,) = reserve.deposits(id);
            assertEq(amount, 0);
            assertEq(reserve.totalDeposited(), INITIAL);
            assertEq(token.balanceOf(ALICE), aliceBefore);
            assertEq(token.balanceOf(address(reserve)), INITIAL);
        }
    }

    function testPayoutFailureRollsBackIdsCountersPendingAndRateBudgetThenRetries() public {
        USDOMReserve.Burn memory b = queued(100);
        mature();
        for (uint256 i = 2; i <= 6; ++i) {
            token.setMode(HostileToken.Mode(i));
            vm.expectRevert();
            reserve.executeWithdrawal(b);
            assertUnpaid(b);
            assertEq(reserve.totalReleased(), 0);
            assertEq(reserve.availableOutflow(), FLOW);
            assertEq(reserve.pendingRequests(b.requestId), b.burnId);
            assertEq(token.balanceOf(address(reserve)), INITIAL);
            assertEq(token.balanceOf(BOB), 0);
        }
        token.setMode(HostileToken.Mode.Standard);
        token.setBlocked(BOB);
        vm.expectRevert();
        reserve.executeWithdrawal(b);
        assertUnpaid(b);
        token.setBlocked(address(reserve));
        vm.expectRevert();
        reserve.executeWithdrawal(b);
        assertUnpaid(b);
        token.setBlocked(address(0));
        reserve.executeWithdrawal(b);
        assertEq(token.balanceOf(BOB), 100);
    }

    function testConfiscationBlocksDepositsAndWithdrawalsUntilCollateralRestored() public {
        USDOMReserve.Burn memory b = queued(100);
        mature();
        token.confiscate(address(reserve), 1);
        vm.expectRevert(USDOMReserve.Insolvent.selector);
        reserve.executeWithdrawal(b);
        vm.prank(ALICE);
        vm.expectRevert(USDOMReserve.Insolvent.selector);
        reserve.deposit(1, bytes32(uint256(2)), bytes32(uint256(2)));
        token.mint(address(reserve), 1);
        reserve.executeWithdrawal(b);
    }

    function testReentrancyDuringDepositCannotReenterDepositQueueOrExecute() public {
        USDOMReserve.Burn memory b = queued(1);
        mature();
        USDOMReserve.Burn memory c = burn(1);
        bytes[3] memory calls = [
            abi.encodeCall(reserve.deposit, (1, bytes32(uint256(9)), bytes32(uint256(9)))),
            abi.encodeCall(reserve.queueWithdrawal, (c, signatures(c))),
            abi.encodeCall(reserve.executeWithdrawal, (b))
        ];
        for (uint256 i; i < 3; ++i) {
            token.setCallback(address(reserve), calls[i]);
            vm.prank(ALICE);
            reserve.deposit(1, bytes32(i + 2), bytes32(uint256(2)));
            assertFalse(token.callbackSucceeded());
            assertEq(bytes32(token.callbackError()), bytes32(ReentrancyGuard.ReentrancyGuardReentrantCall.selector));
        }
        assertUnpaid(b);
    }

    function testReentrancyDuringPayoutCannotEnterAnyValuePath() public {
        USDOMReserve.Burn[3] memory payments = [queued(100), queued(100), queued(100)];
        USDOMReserve.Burn memory other = burn(1);
        bytes[3] memory calls = [
            abi.encodeCall(reserve.executeWithdrawal, (payments[0])),
            abi.encodeCall(reserve.deposit, (1, bytes32(uint256(9)), bytes32(uint256(9)))),
            abi.encodeCall(reserve.queueWithdrawal, (other, signatures(other)))
        ];
        mature();
        for (uint256 i; i < 3; ++i) {
            token.setCallback(address(reserve), calls[i]);
            reserve.executeWithdrawal(payments[i]);
            assertFalse(token.callbackSucceeded());
            assertEq(bytes32(token.callbackError()), bytes32(ReentrancyGuard.ReentrancyGuardReentrantCall.selector));
            assertEq(token.balanceOf(BOB), 100 * (i + 1));
        }
        assertEq(reserve.totalReleased(), 300);
    }

    function testNoAdminSweepUpgradeFallbackOrEtherEntryPoint() public {
        vm.deal(address(governor), 1 ether);
        bytes[4] memory attempts = [
            abi.encodeWithSignature("sweep(address,uint256)", ATTACKER, INITIAL),
            abi.encodeWithSignature("upgradeTo(address)", ATTACKER),
            abi.encodeWithSignature("withdraw(address,uint256)", ATTACKER, INITIAL),
            abi.encodeWithSignature("transfer(address,uint256)", ATTACKER, INITIAL)
        ];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert();
            govern(attempts[i]);
        }
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(reserve).call{value: 1}("");
        assertFalse(ok);
        assertEq(token.balanceOf(address(reserve)), INITIAL);
    }

    function testConstructorRejectsUnsafeConfiguration() public {
        for (uint256 i; i < 14; ++i) {
            USDOMReserve.Config memory c = config();
            if (i == 0) c.token = IERC20(address(0));
            if (i == 1) c.domDomain = bytes32(0);
            if (i == 2) c.governance = ATTACKER;
            if (i == 3) c.guardian = address(0);
            if (i == 4) c.guardian = c.governance;
            if (i == 5) c.governance = address(token);
            if (i == 6) c.guardian = address(token);
            if (i == 7) c.withdrawalDelay = 6 hours - 1;
            if (i == 8) c.withdrawalDelay = 3 days + 1;
            if (i == 9) c.governanceDelay = 2 days - 1;
            if (i == 10) c.governanceDelay = 30 days + 1;
            if (i == 11) c.outflowCapacity = 0;
            if (i == 12) c.maxOutstanding = FLOW - 1;
            if (i == 13) c.guardian = ATTACKER;
            vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
            new USDOMReserve(c, signers, 3);
        }
        token.setDecimals(18);
        USDOMReserve.Config memory wrongDecimals = config();
        vm.expectRevert(USDOMReserve.UnsupportedToken.selector);
        new USDOMReserve(wrongDecimals, signers, 3);
    }

    function testTimestampNarrowingAlwaysFailsClosed() public {
        vm.warp(type(uint64).max);
        vm.expectRevert(USDOMReserve.TimestampOverflow.selector);
        reserve.previewWithdrawal(1);

        USDOMReserve.Burn memory b = burn(1);
        bytes[] memory sigs = signatures(b);
        vm.expectRevert(USDOMReserve.TimestampOverflow.selector);
        reserve.queueWithdrawal(b, sigs);

        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        vm.expectRevert(USDOMReserve.TimestampOverflow.selector);
        govern(abi.encodeCall(reserve.scheduleResume, ()));
        vm.expectRevert(USDOMReserve.TimestampOverflow.selector);
        govern(abi.encodeCall(reserve.proposeNotaries, (signers, 3)));

        vm.warp(uint256(type(uint64).max) + 1);
        vm.expectRevert(USDOMReserve.TimestampOverflow.selector);
        new USDOMReserve(config(), signers, 3);
    }

    function testConstructorAndProposalRejectUnsafeQuorums() public {
        USDOMReserve.Config memory c = config();
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, signers, 2);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, signers, 5);
        address[] memory shortList = new address[](2);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, shortList, 2);
        address[] memory longList = new address[](17);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, longList, 17);
        address[] memory bad = signers;
        bad[1] = bad[0];
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, bad, 3);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        govern(abi.encodeCall(reserve.proposeNotaries, (bad, 3)));
        bad[0] = address(0);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, bad, 3);
        address[] memory roles = new address[](3);
        roles[0] = GUARDIAN;
        roles[1] = address(uint160(type(uint160).max - 1));
        roles[2] = address(type(uint160).max);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        new USDOMReserve(c, roles, 3);
    }

    function testFuzzDepositsPreserveAccounting(uint64 rawAmount, bytes32 salt) public {
        uint64 amount = uint64(uint256(rawAmount) % (CAP - INITIAL)) + 1;
        if (salt == bytes32(uint256(1))) salt = bytes32(uint256(2));
        vm.prank(ALICE);
        reserve.deposit(amount, salt, bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), uint256(INITIAL) + amount);
        assertEq(token.balanceOf(address(reserve)), reserve.outstanding());
    }

    function testFuzzPayoutConservationAndReplay(uint64 rawAmount, address recipient) public {
        if (recipient == address(0) || recipient == address(reserve) || recipient == address(token)) recipient = BOB;
        uint64 amount = uint64(uint256(rawAmount) % FLOW) + 1;
        USDOMReserve.Burn memory b = burn(amount);
        b.recipient = recipient;
        uint256 beforeBalance = token.balanceOf(recipient);
        reserve.queueWithdrawal(b, signatures(b));
        mature();
        reserve.executeWithdrawal(b);
        assertEq(token.balanceOf(recipient), beforeBalance + amount);
        assertEq(reserve.outstanding() + reserve.totalReleased(), reserve.totalDeposited());
        assertEq(token.balanceOf(address(reserve)), reserve.outstanding());
        vm.expectRevert(USDOMReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(b);
    }

    function testFuzzMutatedCertificateCannotQueue(uint64 rawAmount, bytes32 changedRequest) public {
        USDOMReserve.Burn memory b = burn(uint64(uint256(rawAmount) % FLOW) + 1);
        bytes[] memory sigs = signatures(b);
        if (changedRequest == b.requestId) changedRequest = bytes32(0);
        b.requestId = changedRequest;
        vm.expectRevert();
        reserve.queueWithdrawal(b, sigs);
        assertEq(reserve.totalReleased(), 0);
    }

    function testFuzzBucketConservativeBound(uint32 elapsed) public {
        USDOMReserve.Burn memory b = queued(FLOW);
        mature();
        reserve.executeWithdrawal(b);
        vm.warp(block.timestamp + elapsed);
        uint256 expected = elapsed >= 1 days ? FLOW : uint256(elapsed) * FLOW / 1 days;
        assertEq(reserve.availableOutflow(), expected);
        assertTrue(reserve.availableOutflow() <= FLOW);
    }

    function testCompromisedQuorumCanLieButCannotBypassDelayOrOutflowCap() public {
        // Deliberately no DOM burn proof exists. This executable counterexample is
        // the bridge trust limit, NOT evidence of autonomous DOM verification.
        USDOMReserve.Burn memory fabricated = queued(FLOW);
        USDOMReserve.Burn memory more = queued(1);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeWithdrawal(fabricated);
        mature();
        reserve.executeWithdrawal(fabricated);
        vm.expectRevert(USDOMReserve.OutflowLimit.selector);
        reserve.executeWithdrawal(more);
        assertEq(reserve.totalReleased(), FLOW);
    }
}
