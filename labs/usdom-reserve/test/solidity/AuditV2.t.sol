// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {ReserveFixture} from "./USDOMReserve.t.sol";

contract AuditV2Test is ReserveFixture {
    function nextSet(uint256 start) internal returns (address[] memory result) {
        result = new address[](4);
        for (uint256 i; i < 4; ++i) {
            keys[i] = start + i;
            result[i] = vm.addr(keys[i]);
        }
        for (uint256 i; i < 4; ++i) {
            for (uint256 j = i + 1; j < 4; ++j) {
                if (result[j] < result[i]) {
                    (result[i], result[j]) = (result[j], result[i]);
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
    }

    function emergency() internal {
        vm.prank(GUARDIAN);
        reserve.pause();
    }

    function propose(address[] memory set) internal {
        govern(abi.encodeCall(reserve.proposeNotaries, (set, 3)));
    }

    function install(address[] memory set) internal {
        vm.warp(reserve.notariesReadyAt());
        reserve.executeNotaries(set, 3);
    }

    function schedule() internal {
        govern(abi.encodeCall(reserve.scheduleResume, ()));
    }

    function finishResume() internal {
        vm.warp(reserve.resumeReadyAt());
        reserve.executeResume();
    }

    function testEpochBoundEmergencyCannotRevokeReplacementKeys() public {
        uint64 observed = reserve.currentEpoch();
        address[] memory next = nextSet(80001);
        propose(next);
        install(next);
        vm.prank(GUARDIAN);
        vm.expectRevert(USDOMReserve.StaleEmergency.selector);
        reserve.pauseEpoch(observed);
        assertFalse(reserve.paused());
        for (uint256 i; i < next.length; ++i) {
            assertFalse(reserve.revokedNotary(next[i]));
        }
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        assertTrue(reserve.paused());
        for (uint256 i; i < next.length; ++i) {
            assertFalse(reserve.revokedNotary(next[i]));
        }
    }

    function testEpochBoundEmergencyRevokesOnlyWithAuthorizationAndCurrentEpoch() public {
        uint64 observed = reserve.currentEpoch();
        vm.prank(ATTACKER);
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.pauseEpoch(observed);
        assertFalse(reserve.paused());
        vm.prank(GUARDIAN);
        reserve.pauseEpoch(observed);
        assertTrue(reserve.paused());
        assertTrue(reserve.recoveryRequired());
        for (uint256 i; i < signers.length; ++i) {
            assertTrue(reserve.revokedNotary(signers[i]));
        }
    }

    function testV2EmergencyCannotResumeBeforeFreshInstallation() public {
        USDOMReserve.Burn memory old = queued(FLOW);
        emergency();
        assertTrue(reserve.recoveryRequired());
        for (uint256 i; i < signers.length; ++i) {
            assertTrue(reserve.revokedNotary(signers[i]));
        }
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        schedule();
        vm.prank(GUARDIAN);
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        reserve.pauseOperational();
        vm.expectRevert(USDOMReserve.RevokedNotary.selector);
        propose(signers);
        address[] memory next = nextSet(10001);
        propose(next);
        vm.expectRevert(USDOMReserve.RotationPending.selector);
        schedule();
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeResume();
        install(next);
        assertTrue(reserve.paused());
        assertEq(reserve.resumeReadyAt(), 0);
        schedule();
        assertEq(reserve.resumeEpoch(), reserve.currentEpoch());
        assertEq(reserve.resumeConfigHash(), keccak256(abi.encode(next, uint8(3))));
        vm.warp(reserve.resumeReadyAt() - 1);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeResume();
        finishResume();
        vm.expectRevert(USDOMReserve.StaleCertificate.selector);
        reserve.executeWithdrawal(old);
        assertEq(reserve.totalReleased(), 0);
        assertFalse(reserve.recoveryRequired());
        assertEq(reserve.resumeEpoch(), 0);
        assertEq(reserve.resumeConfigHash(), bytes32(0));
        USDOMReserve.Burn memory fresh = queued(100e6);
        mature();
        reserve.executeWithdrawal(fresh);
        assertEq(reserve.totalReleased(), 100e6);
    }

    function testV2CancelledRecoveryStillRequiresInstallation() public {
        emergency();
        address[] memory next = nextSet(11001);
        propose(next);
        vm.prank(GUARDIAN);
        reserve.cancelNotariesProposal();
        vm.warp(block.timestamp + 5 days);
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        schedule();
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeResume();
        assertTrue(reserve.paused());
        propose(next);
        install(next);
        schedule();
        finishResume();
        assertFalse(reserve.paused());
    }

    function testV2ReplacingPendingRecoveryNeverPreservesResume() public {
        emergency();
        address[] memory next = nextSet(12001);
        propose(next);
        vm.warp(block.timestamp + 1 days);
        address[] memory other = nextSet(13001);
        propose(other);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeNotaries(other, 3);
        vm.expectRevert(USDOMReserve.RotationPending.selector);
        schedule();
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeResume();
        install(other);
        schedule();
        finishResume();
        assertEq(reserve.currentConfigHash(), keccak256(abi.encode(other, uint8(3))));
    }

    function testV2NewProposalClearsAlreadyAuthorizedResumeAndCancelDoesNotRestoreIt() public {
        emergency();
        address[] memory next = nextSet(14001);
        propose(next);
        install(next);
        schedule();
        uint64 oldReady = reserve.resumeReadyAt();
        address[] memory other = nextSet(15001);
        propose(other);
        assertEq(reserve.resumeReadyAt(), 0);
        vm.prank(GUARDIAN);
        reserve.cancelNotariesProposal();
        vm.warp(oldReady);
        vm.expectRevert(USDOMReserve.NoProposal.selector);
        reserve.executeResume();
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        schedule();
        propose(other);
        install(other);
        schedule();
        finishResume();
        assertEq(reserve.currentEpoch(), 3);
    }

    function testV2ProposalPredatingEmergencyCannotReinstallRevokedKeys() public {
        propose(signers);
        emergency();
        vm.warp(reserve.notariesReadyAt());
        vm.expectRevert(USDOMReserve.RevokedNotary.selector);
        reserve.executeNotaries(signers, 3);
        assertEq(reserve.currentEpoch(), 1);
        vm.prank(GUARDIAN);
        reserve.cancelNotariesProposal();
        address[] memory next = nextSet(16001);
        propose(next);
        install(next);
        schedule();
        finishResume();
        vm.expectRevert(USDOMReserve.RevokedNotary.selector);
        propose(signers);
    }

    function testV2FreshProposalPredatingEmergencyCanRecoverButNeedsNewResumeDelay() public {
        address[] memory next = nextSet(17001);
        propose(next);
        vm.warp(reserve.notariesReadyAt());
        emergency();
        reserve.executeNotaries(next, 3);
        schedule();
        assertEq(reserve.resumeReadyAt(), block.timestamp + 2 days);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeResume();
        finishResume();
        assertFalse(reserve.paused());
    }

    function testV2SecondEmergencyRevokesReplacementAndCancelsResume() public {
        emergency();
        address[] memory next = nextSet(18001);
        propose(next);
        install(next);
        schedule();
        emergency();
        assertEq(reserve.recoveryEpoch(), 2);
        assertEq(reserve.resumeReadyAt(), 0);
        for (uint256 i; i < next.length; ++i) {
            assertTrue(reserve.revokedNotary(next[i]));
        }
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        schedule();
        address[] memory other = nextSet(19001);
        propose(other);
        install(other);
        schedule();
        finishResume();
        assertEq(reserve.currentEpoch(), 3);
    }

    function testV2OperationalPauseWithPendingRotationCannotCancelIntoResume() public {
        propose(signers);
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        assertTrue(reserve.recoveryRequired());
        vm.prank(GUARDIAN);
        reserve.cancelNotariesProposal();
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        schedule();
        // An operational pause may keep keys, but must finish a new generation.
        propose(signers);
        install(signers);
        schedule();
        finishResume();
        assertEq(reserve.currentEpoch(), 2);
        for (uint256 i; i < signers.length; ++i) {
            assertFalse(reserve.revokedNotary(signers[i]));
        }
    }

    function testV2OperationalPauseWithoutIncidentPreservesCertificates() public {
        USDOMReserve.Burn memory b = queued(100e6);
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        schedule();
        finishResume();
        reserve.executeWithdrawal(b);
        assertEq(reserve.totalReleased(), 100e6);
        assertEq(reserve.currentEpoch(), 1);
    }

    function testV2OperationalPauseThenProposalAndCancelRequiresNewEpoch() public {
        vm.prank(GUARDIAN);
        reserve.pauseOperational();
        schedule();
        propose(signers);
        assertEq(reserve.resumeReadyAt(), 0);
        vm.prank(GUARDIAN);
        reserve.cancelNotariesProposal();
        vm.expectRevert(USDOMReserve.RecoveryRequired.selector);
        schedule();
        propose(signers);
        install(signers);
        schedule();
        finishResume();
        assertFalse(reserve.paused());
    }

    function testV2OldKeysCannotSignNewEpochAfterEmergency() public {
        uint256[4] memory oldKeys = keys;
        emergency();
        address[] memory next = nextSet(20001);
        propose(next);
        install(next);
        schedule();
        finishResume();
        USDOMReserve.Burn memory b = burn(1);
        keys = oldKeys;
        bytes[] memory sigs = signatures(b);
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(b, sigs);
    }

    function testV2OrdinaryRotationDoesNotPermanentlyRevokePreviousSet() public {
        address[] memory next = nextSet(21001);
        propose(next);
        install(next);
        for (uint256 i; i < signers.length; ++i) {
            assertFalse(reserve.revokedNotary(signers[i]));
        }
        propose(signers);
        install(signers);
        assertEq(reserve.currentEpoch(), 3);
    }

    function testV2UnauthorizedEmergencyAndOperationalActionsLeaveStateUnchanged() public {
        vm.startPrank(ATTACKER);
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.pause();
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.pauseOperational();
        vm.expectRevert(USDOMReserve.Unauthorized.selector);
        reserve.scheduleResume();
        vm.stopPrank();
        assertFalse(reserve.paused());
        assertFalse(reserve.recoveryRequired());
        for (uint256 i; i < signers.length; ++i) {
            assertFalse(reserve.revokedNotary(signers[i]));
        }
    }

    function testV2RefillEstimateIsNotCertificateReadinessOrPausePermission() public {
        USDOMReserve.Burn memory b = queued(FLOW);
        assertEq(reserve.secondsUntilOutflow(FLOW), 0);
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeWithdrawal(b);
        emergency();
        assertEq(reserve.secondsUntilOutflow(FLOW), 0);
        vm.expectRevert(USDOMReserve.IsPaused.selector);
        reserve.executeWithdrawal(b);
        vm.expectRevert(USDOMReserve.InvalidBurn.selector);
        reserve.secondsUntilOutflow(0);
        vm.expectRevert(USDOMReserve.OutflowLimit.selector);
        reserve.secondsUntilOutflow(FLOW + 1);
    }

    function testFuzzV2RefillEstimateIsEarliestTime(uint64 rawCap, uint64 rawAmount, uint32 rawElapsed) public {
        uint64 capacity = rawCap == 0 ? 1 : rawCap;
        USDOMReserve.Config memory c = config();
        c.maxOutstanding = capacity;
        c.outflowCapacity = capacity;
        reserve = new USDOMReserve(c, signers, 3);
        token.mint(ALICE, capacity);
        vm.startPrank(ALICE);
        token.approve(address(reserve), capacity);
        reserve.deposit(capacity, bytes32(uint256(1)), bytes32(uint256(1)));
        vm.stopPrank();
        USDOMReserve.Burn memory b = queued(capacity);
        uint256 origin = block.timestamp + 1 days;
        vm.warp(origin);
        reserve.executeWithdrawal(b);
        uint256 elapsed = uint256(rawElapsed) % (2 days);
        vm.warp(origin + elapsed);
        uint64 amount = uint64(uint256(rawAmount) % capacity) + 1;
        uint256 delta = reserve.secondsUntilOutflow(amount);
        if (delta == 0) {
            assertTrue(reserve.availableOutflow() >= amount);
            return;
        }
        assertTrue(delta <= 1 days);
        vm.warp(origin + elapsed + delta - 1);
        assertTrue(reserve.availableOutflow() < amount);
        vm.warp(origin + elapsed + delta);
        assertTrue(reserve.availableOutflow() >= amount);
        assertEq(reserve.secondsUntilOutflow(amount), 0);
    }
}
