// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReserveFixture} from "./USDOMReserve.t.sol";

contract HostilePolicyReturnToken {
    uint256 private immutable responseMode;

    constructor(uint256 responseMode_) {
        responseMode = responseMode_;
    }

    fallback() external {
        uint256 mode = responseMode;
        assembly {
            let selector := shr(224, calldataload(0))
            // decimals()
            if eq(selector, 0x313ce567) {
                mstore(0, 6)
                return(0, 32)
            }
            // paused(): dirty boolean or bounded-copy return bomb.
            if eq(selector, 0x5c975abb) {
                if eq(mode, 1) {
                    mstore(0, 2)
                    return(0, 32)
                }
                mstore(0, 0)
                return(0, 0x100000)
            }
            mstore(0, 0)
            return(0, 32)
        }
    }
}

contract USDTPolicyTest is ReserveFixture {
    function unsafePolicy(uint256 variant) private {
        token.setPolicy(variant == 0, variant == 1, variant == 2 ? 1 : 0, variant == 3 ? 1 : 0, variant == 4);
    }

    function testPolicyReturnBombAndDirtyBooleanFailClosedAtBoundedBoundary() public {
        for (uint256 mode = 1; mode <= 2; ++mode) {
            HostilePolicyReturnToken hostile = new HostilePolicyReturnToken(mode);
            USDOMReserve.Config memory candidate = config();
            candidate.token = IERC20(address(hostile));
            vm.expectRevert(USDOMReserve.UnsupportedToken.selector);
            new USDOMReserve(candidate, signers, 3);
        }
    }

    function testUnsafePolicyRejectsDeploymentAndDepositWithoutConsumingId() public {
        bytes32 salt = keccak256("policy deposit");
        bytes32 id = reserve.depositId(ALICE, salt);
        uint256 balance = token.balanceOf(ALICE);
        for (uint256 i; i < 5; ++i) {
            unsafePolicy(i);
            vm.expectRevert();
            new USDOMReserve(config(), signers, 3);
            vm.prank(ALICE);
            vm.expectRevert();
            reserve.deposit(1, salt, bytes32(uint256(1)));
            (address funder,,) = reserve.deposits(id);
            assertEq(funder, address(0));
            assertEq(reserve.totalDeposited(), INITIAL);
            assertEq(token.balanceOf(ALICE), balance);
        }
        token.setPolicy(false, false, 0, 0, false);
        vm.prank(ALICE);
        assertEq(reserve.deposit(1, salt, bytes32(uint256(1))), id);
    }

    function testLegacyUpgradeTargetFailsClosedEvenIfDeprecatedFlagIsFalse() public {
        token.setUpgradedAddress(address(0x1234));
        vm.expectRevert(USDOMReserve.UnsafeTokenState.selector);
        new USDOMReserve(config(), signers, 3);

        bytes32 salt = keccak256("prototype legacy upgrade target");
        bytes32 id = reserve.depositId(ALICE, salt);
        vm.prank(ALICE);
        vm.expectRevert(USDOMReserve.UnsafeTokenState.selector);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        (address funder,,) = reserve.deposits(id);
        assertEq(funder, address(0));
        assertEq(reserve.totalDeposited(), INITIAL);
    }

    function testUnsafePolicyRejectsAdmissionWithoutReservingIdsOrCredit() public {
        USDOMReserve.Burn memory b = burn(1);
        bytes[] memory sigs = signatures(b);
        for (uint256 i; i < 5; ++i) {
            unsafePolicy(i);
            vm.expectRevert();
            reserve.queueWithdrawal(b, sigs);
            assertEq(reserve.totalPendingAmount(), 0);
            assertEq(reserve.pendingRequests(b.requestId), bytes32(0));
            assertUnpaid(b);
        }
        token.setPolicy(false, false, 0, 0, false);
        reserve.queueWithdrawal(b, sigs);
        assertEq(reserve.totalPendingAmount(), b.amount);
    }

    function testChangedPolicyCannotConsumeQueuedBurnOrOutflowAndCanRetry() public {
        USDOMReserve.Burn memory b = queued(100e6);
        mature();
        uint256 available = reserve.availableOutflow();
        for (uint256 i; i < 5; ++i) {
            unsafePolicy(i);
            vm.expectRevert();
            reserve.executeWithdrawal(b);
            assertUnpaid(b);
            assertEq(reserve.totalReleased(), 0);
            assertEq(reserve.totalPendingAmount(), b.amount);
            assertEq(reserve.pendingRequests(b.requestId), b.burnId);
            assertEq(reserve.availableOutflow(), available);
            assertEq(token.balanceOf(BOB), 0);
        }
        token.setPolicy(false, false, 0, 0, false);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalReleased(), b.amount);
    }

    function testFrozenFunderOrReserveCannotDeposit() public {
        for (uint256 i; i < 2; ++i) {
            address frozen = i == 0 ? ALICE : address(reserve);
            token.setBlocked(frozen);
            vm.prank(ALICE);
            vm.expectRevert(abi.encodeWithSelector(USDOMReserve.FrozenTokenAccount.selector, frozen));
            reserve.deposit(1, bytes32(uint256(99)), bytes32(uint256(1)));
            assertEq(reserve.totalDeposited(), INITIAL);
        }
    }

    function testFrozenRecipientCannotQueueAndFreezingAfterQueuePreservesClaim() public {
        USDOMReserve.Burn memory b = burn(100e6);
        bytes[] memory sigs = signatures(b);
        token.setBlocked(BOB);
        vm.expectRevert(abi.encodeWithSelector(USDOMReserve.FrozenTokenAccount.selector, BOB));
        reserve.queueWithdrawal(b, sigs);
        token.setBlocked(address(0));
        reserve.queueWithdrawal(b, sigs);
        mature();
        for (uint256 i; i < 2; ++i) {
            address frozen = i == 0 ? BOB : address(reserve);
            token.setBlocked(frozen);
            vm.expectRevert(abi.encodeWithSelector(USDOMReserve.FrozenTokenAccount.selector, frozen));
            reserve.executeWithdrawal(b);
            assertUnpaid(b);
            assertEq(reserve.totalPendingAmount(), b.amount);
            assertEq(reserve.totalReleased(), 0);
        }
        token.setBlocked(address(0));
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
    }

    function testChangedTokenRuntimeCannotMutateCollateralLedger() public {
        bytes memory originalRuntime = address(token).code;
        assertEq(uint256(reserve.tokenCodeHash()), uint256(address(token).codehash));
        vm.etch(address(token), hex"00");

        vm.prank(ALICE);
        vm.expectRevert(USDOMReserve.TokenChanged.selector);
        reserve.deposit(1, bytes32(uint256(901)), bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), INITIAL);
        assertEq(reserve.totalReleased(), 0);
        assertEq(reserve.totalPendingAmount(), 0);

        vm.etch(address(token), originalRuntime);
        assertEq(uint256(reserve.tokenCodeHash()), uint256(address(token).codehash));
    }

    function testQuorumPrototypeCannotDeployOnEthereumMainnet() public {
        vm.chainId(1);
        vm.expectRevert(USDOMReserve.PrototypeOnly.selector);
        new USDOMReserve(config(), signers, 3);
    }
}
