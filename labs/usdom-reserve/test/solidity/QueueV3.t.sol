// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {ReserveFixture} from "./USDOMReserve.t.sol";

contract QueueV3Test is ReserveFixture {
    function testBlockedRecipientDoesNotBlockOtherWithdrawals() public {
        USDOMReserve.Burn memory a = queued(100);
        USDOMReserve.Burn memory b = burn(100);
        b.recipient = ALICE;
        reserve.queueWithdrawal(b, signatures(b));
        token.setBlocked(BOB);
        mature();
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.executeWithdrawal, (a)));
        assertFalse(ok);
        reserve.executeWithdrawal(b);
        assertEq(reserve.totalPendingAmount(), 100);
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.firstPendingBurn(), a.burnId);
        assertEq(reserve.lastPendingBurn(), a.burnId);
        token.setBlocked(address(0));
        reserve.executeWithdrawal(a);
        assertEq(reserve.pendingCount(), 0);
    }

    function testExpiredMiddleAndTailDoNotCorruptLinks() public {
        USDOMReserve.Burn memory a = queued(10);
        USDOMReserve.Burn memory b = burn(20);
        b.validUntil = uint64(block.timestamp + 2 days);
        reserve.queueWithdrawal(b, signatures(b));
        USDOMReserve.Burn memory c = burn(30);
        c.validUntil = b.validUntil;
        reserve.queueWithdrawal(c, signatures(c));
        vm.warp(uint256(b.validUntil) + 1);
        reserve.discardWithdrawal(b.burnId);
        reserve.discardWithdrawal(c.burnId);
        assertEq(reserve.firstPendingBurn(), a.burnId);
        assertEq(reserve.lastPendingBurn(), a.burnId);
        assertEq(reserve.totalPendingAmount(), 10);
        reserve.executeWithdrawal(a);
        assertEq(reserve.pendingCount(), 0);
    }

    function testOldEpochCleanupDoesNotEraseNewQueue() public {
        USDOMReserve.Burn memory a = queued(10);
        govern(abi.encodeCall(reserve.proposeNotaries, (signers, 3)));
        vm.warp(block.timestamp + 2 days);
        reserve.executeNotaries(signers, 3);
        assertEq(reserve.totalPendingAmount(), 0);
        USDOMReserve.Burn memory b = queued(20);
        reserve.discardWithdrawal(a.burnId);
        assertEq(reserve.firstPendingBurn(), b.burnId);
        assertEq(reserve.totalPendingAmount(), 20);
        mature();
        reserve.executeWithdrawal(b);
    }

    function testPruneCannotCancelValidCertificatesAndIsBounded() public {
        USDOMReserve.Burn memory a = queued(10);
        queued(20);
        assertEq(reserve.pruneExpired(2), 0);
        vm.warp(uint256(a.validUntil) + 1);
        assertEq(reserve.pruneExpired(1), 1);
        assertEq(reserve.totalPendingAmount(), 20);
        assertEq(reserve.pruneExpired(256), 1);
        assertEq(reserve.totalPendingAmount(), 0);
        vm.expectRevert(USDOMReserve.InvalidConfiguration.selector);
        reserve.pruneExpired(257);
    }

    function testDustEntriesCannotExhaustAnArtificialQueueSlotCap() public {
        for (uint256 i; i < 256; ++i) {
            queued(1);
        }
        USDOMReserve.Burn memory b = burn(1);
        bytes[] memory sigs = signatures(b);
        reserve.queueWithdrawal(b, sigs);
        assertEq(reserve.pendingCount(), 257);
    }

    function testFuzzReservedCreditConservedAcrossPaymentOrder(uint64 x, uint64 y, uint64 z) public {
        uint64[3] memory amounts = [uint64(x % (FLOW / 3) + 1), uint64(y % (FLOW / 3) + 1), uint64(z % (FLOW / 3) + 1)];
        USDOMReserve.Burn[3] memory burns;
        for (uint256 i; i < 3; ++i) {
            burns[i] = queued(amounts[i]);
        }
        uint256 sum = uint256(amounts[0]) + amounts[1] + amounts[2];
        assertEq(reserve.totalPendingAmount(), sum);
        mature();
        reserve.executeWithdrawal(burns[1]);
        reserve.executeWithdrawal(burns[2]);
        reserve.executeWithdrawal(burns[0]);
        assertEq(token.balanceOf(BOB), sum);
        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.firstPendingBurn(), bytes32(0));
        assertEq(reserve.lastPendingBurn(), bytes32(0));
    }

    function testMassExitExposesExpiryAndRequiresFreshAttestation() public {
        vm.prank(ALICE);
        reserve.deposit(CAP - INITIAL, bytes32(uint256(2)), bytes32(uint256(2)));
        USDOMReserve.Burn[] memory claims = new USDOMReserve.Burn[](50);
        uint256 start = block.timestamp;
        for (uint256 i; i < claims.length; ++i) {
            claims[i] = queued(FLOW);
        }

        // Six-day certificates and one-day maturity permit six full buckets,
        // not all fifty claims. This is measured unavailability, not a liveness proof.
        for (uint256 i; i < 6; ++i) {
            vm.warp(start + (i + 1) * 1 days);
            reserve.executeWithdrawal(claims[i]);
        }
        assertEq(reserve.totalReleased(), 12_000e6);
        assertEq(reserve.outstanding(), 88_000e6);
        vm.warp(start + 6 days + 1);
        for (uint256 i = 6; i < claims.length; ++i) {
            vm.expectRevert(USDOMReserve.StaleCertificate.selector);
            reserve.executeWithdrawal(claims[i]);
            assertUnpaid(claims[i]);
        }

        USDOMReserve.Burn memory retry = claims[6];
        reserve.discardWithdrawal(retry.burnId);
        retry.validUntil = uint64(block.timestamp + 6 days);
        // Relayer cannot silently extend deadline or reattest without quorum.
        bytes[] memory empty = new bytes[](0);
        vm.expectRevert(USDOMReserve.InvalidQuorum.selector);
        reserve.queueWithdrawal(retry, empty);
        reserve.queueWithdrawal(retry, signatures(retry));
        vm.expectRevert(USDOMReserve.TooEarly.selector);
        reserve.executeWithdrawal(retry);
        mature();
        reserve.executeWithdrawal(retry);
        assertEq(reserve.totalReleased(), 14_000e6);
        assertEq(token.balanceOf(BOB), 14_000e6);
        assertEq(reserve.outstanding(), 86_000e6);
    }
}
