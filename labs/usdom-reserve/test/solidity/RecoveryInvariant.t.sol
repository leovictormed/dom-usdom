// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;
import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {MockGovernance} from "./Mocks.sol";
import {TestBase} from "./TestBase.sol";
import {ReserveFixture} from "./USDOMReserve.t.sol";

contract RecoveryHandler is TestBase {
    USDOMReserve public immutable reserve;
    MockGovernance private governor;
    address[] private active;
    address[] private proposed;
    address[] private permanentlyRevoked;
    uint256 private serial;
    uint256 public minimumResumeEpoch;
    uint256 public authorizedAt;
    uint256 public authorizedEpoch;
    bytes32 public authorizedConfig;
    uint256 public successfulRecoveries;

    constructor(USDOMReserve r, MockGovernance g, address[] memory initial) {
        reserve = r;
        governor = g;
        active = initial;
    }

    function clearAuthorization() private {
        authorizedAt = 0;
        authorizedEpoch = 0;
        authorizedConfig = bytes32(0);
    }

    function emergency() external {
        vm.prank(reserve.guardian());
        reserve.pause();
        minimumResumeEpoch = reserve.currentEpoch() + 1;
        clearAuthorization();
        for (uint256 i; i < active.length; ++i) {
            permanentlyRevoked.push(active[i]);
        }
    }

    function operational() external {
        vm.prank(reserve.guardian());
        try reserve.pauseOperational() {
            clearAuthorization();
            if (reserve.proposedNotariesHash() != bytes32(0)) minimumResumeEpoch = reserve.currentEpoch() + 1;
        } catch {
            assertTrue(reserve.recoveryRequired());
        }
    }

    function propose() external {
        ++serial;
        address[] memory next = new address[](3);
        for (uint256 i; i < 3; ++i) {
            next[i] = address(uint160(0x100000 + serial * 3 + i));
        }
        governor.execute(address(reserve), abi.encodeCall(reserve.proposeNotaries, (next, 3)));
        proposed = next;
        clearAuthorization();
        if (reserve.paused()) minimumResumeEpoch = reserve.currentEpoch() + 1;
    }

    function cancel() external {
        vm.prank(reserve.guardian());
        try reserve.cancelNotariesProposal() {
            delete proposed;
            clearAuthorization();
        } catch {
            assertEq(reserve.proposedNotariesHash(), bytes32(0));
        }
    }

    function rotate() external {
        try reserve.executeNotaries(proposed, 3) {
            active = proposed;
            delete proposed;
            clearAuthorization();
        } catch {}
    }

    function schedule() external {
        bool expected = reserve.paused() && reserve.proposedNotariesHash() == bytes32(0)
            && reserve.currentEpoch() >= minimumResumeEpoch;
        (bool ok,) = address(governor)
            .call(abi.encodeCall(governor.execute, (address(reserve), abi.encodeCall(reserve.scheduleResume, ()))));
        assertTrue(ok == expected);
        if (ok) {
            authorizedAt = block.timestamp + reserve.governanceDelay();
            authorizedEpoch = reserve.currentEpoch();
            authorizedConfig = keccak256(abi.encode(active, uint8(3)));
            // Initial fixture is 3/4; hash still binds the exact address list and threshold.
            assertEq(reserve.resumeReadyAt(), authorizedAt);
        }
    }

    function resume() external {
        bool expected = reserve.paused() && authorizedAt != 0 && block.timestamp >= authorizedAt
            && reserve.currentEpoch() >= minimumResumeEpoch && reserve.currentEpoch() == authorizedEpoch
            && reserve.currentConfigHash() == authorizedConfig && reserve.proposedNotariesHash() == bytes32(0);
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.executeResume, ()));
        assertTrue(ok == expected);
        if (ok) {
            ++successfulRecoveries;
            minimumResumeEpoch = 0;
            clearAuthorization();
        }
    }

    function advance(uint32 elapsed) external {
        vm.warp(block.timestamp + uint256(elapsed) % 5 days);
    }

    function unauthorized(uint8 choice) external {
        bytes memory data =
            choice % 2 == 0 ? abi.encodeCall(reserve.pause, ()) : abi.encodeCall(reserve.pauseOperational, ());
        (bool ok,) = address(reserve).call(data);
        assertFalse(ok);
    }

    function check() external view {
        assertEq(reserve.currentConfigHash(), keccak256(abi.encode(active, uint8(3))));
        if (!reserve.paused()) {
            assertFalse(reserve.recoveryRequired());
            for (uint256 i; i < active.length; ++i) {
                assertFalse(reserve.revokedNotary(active[i]));
            }
        }
        for (uint256 i; i < permanentlyRevoked.length; ++i) {
            assertTrue(reserve.revokedNotary(permanentlyRevoked[i]));
        }
        assertEq(reserve.resumeReadyAt(), authorizedAt);
        assertEq(reserve.resumeEpoch(), authorizedEpoch);
        assertEq(reserve.resumeConfigHash(), authorizedConfig);
        assertEq(reserve.totalReleased(), 0);
    }
}

contract RecoveryInvariantTest is ReserveFixture {
    RecoveryHandler public handler;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function setUp() public override {
        super.setUp();
        handler = new RecoveryHandler(reserve, governor, signers);
    }

    function targetContracts() public view returns (address[] memory a) {
        a = new address[](1);
        a[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory a) {
        bytes4[] memory s = new bytes4[](9);
        s[0] = handler.emergency.selector;
        s[1] = handler.operational.selector;
        s[2] = handler.propose.selector;
        s[3] = handler.cancel.selector;
        s[4] = handler.rotate.selector;
        s[5] = handler.schedule.selector;
        s[6] = handler.resume.selector;
        s[7] = handler.advance.selector;
        s[8] = handler.unauthorized.selector;
        a = new FuzzSelector[](1);
        a[0] = FuzzSelector(address(handler), s);
    }

    function invariantRecoveryRequiresInstallationAndBoundDelayedAuthorization() public view {
        handler.check();
    }
}
