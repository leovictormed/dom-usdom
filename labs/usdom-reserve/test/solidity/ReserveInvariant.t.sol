// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {USDOMReserve} from "../../contracts/USDOMReserve.sol";
import {HostileToken, MockGovernance} from "./Mocks.sol";
import {TestBase} from "./TestBase.sol";
import {ReserveFixture} from "./USDOMReserve.t.sol";

/// Stateful attacker/environment: assertions use independently accumulated
/// deposits, donations and payouts, not merely equivalent contract getters.
contract ReserveHandler is TestBase {
    USDOMReserve public immutable reserve;
    HostileToken public immutable token;
    MockGovernance public immutable governor;
    address public immutable guardian;
    address public constant RECIPIENT = address(0xB0B);
    uint256[4] private keys;
    address[] private signers;
    USDOMReserve.Burn[] private requests;
    uint256 private nonce;
    uint256 public ghostDeposited;
    uint256 public ghostPaid;
    uint256 public ghostDonated;
    uint256 public immutable startTime;
    uint256 public successfulDeposits;
    uint256 public successfulQueues;
    uint256 public successfulPayouts;
    mapping(bytes32 => bool) public observedBurns;
    mapping(bytes32 => bool) public observedRequests;

    constructor(
        USDOMReserve reserve_,
        HostileToken token_,
        MockGovernance governor_,
        uint256[4] memory keys_,
        address[] memory signers_
    ) {
        reserve = reserve_;
        token = token_;
        governor = governor_;
        guardian = reserve_.guardian();
        keys = keys_;
        signers = signers_;
        ghostDeposited = reserve_.totalDeposited();
        startTime = block.timestamp;
        token_.approve(address(reserve_), type(uint256).max);
    }

    function deposit(uint64 raw) external {
        uint256 room = reserve.maxOutstanding() - reserve.outstanding();
        if (room == 0 || reserve.paused()) return;
        uint64 amount = uint64(uint256(raw) % room) + 1;
        if (token.balanceOf(address(this)) < amount) token.mint(address(this), amount);
        reserve.deposit(amount, bytes32(++nonce), bytes32(uint256(1)));
        ghostDeposited += amount;
        ++successfulDeposits;
    }

    function queue(uint64 raw) external {
        uint256 bound = reserve.unreservedCollateral();
        if (reserve.outflowCapacity() < bound) bound = reserve.outflowCapacity();
        if (bound == 0 || reserve.paused()) return;
        USDOMReserve.Burn memory b = makeBurn(uint64(uint256(raw) % bound) + 1);
        (uint64 slot,) = reserve.previewWithdrawal(b.amount);
        if (uint256(slot) + reserve.MIN_EXECUTION_WINDOW() > b.validUntil) return;
        reserve.queueWithdrawal(b, sign(b));
        requests.push(b);
        ++successfulQueues;
    }

    function execute(uint256 index) external {
        if (requests.length == 0) return;
        USDOMReserve.Burn memory b = requests[index % requests.length];
        uint256 beforeBalance = token.balanceOf(RECIPIENT);
        uint256 beforeReleased = reserve.totalReleased();
        try reserve.executeWithdrawal(b) {
            require(!observedBurns[b.burnId] && !observedRequests[b.requestId], "duplicate payment");
            observedBurns[b.burnId] = true;
            observedRequests[b.requestId] = true;
            ghostPaid += b.amount;
            ++successfulPayouts;
            assertEq(token.balanceOf(RECIPIENT), beforeBalance + b.amount);
        } catch {
            assertEq(token.balanceOf(RECIPIENT), beforeBalance);
            assertEq(reserve.totalReleased(), beforeReleased);
        }
    }

    function advance(uint32 seconds_) external {
        vm.warp(block.timestamp + uint256(seconds_) % 3 days);
    }

    function donate(uint64 raw) external {
        uint64 amount = raw % 1_000e6;
        token.mint(address(reserve), amount);
        ghostDonated += amount;
    }

    function recoverable() private view returns (bool) {
        return reserve.proposedNotariesHash() == bytes32(0)
            && (!reserve.recoveryRequired() || reserve.currentEpoch() > reserve.recoveryEpoch());
    }

    function pause() external {
        if (reserve.recoveryRequired()) return;
        vm.prank(guardian);
        reserve.pauseOperational();
    }

    function scheduleResume() external {
        if (reserve.paused() && recoverable()) {
            governor.execute(address(reserve), abi.encodeCall(reserve.scheduleResume, ()));
        }
    }

    function resume() external {
        if (!reserve.paused() || !recoverable()) return;
        if (reserve.resumeReadyAt() == 0) {
            governor.execute(address(reserve), abi.encodeCall(reserve.scheduleResume, ()));
        }
        if (block.timestamp < reserve.resumeReadyAt()) vm.warp(reserve.resumeReadyAt());
        reserve.executeResume();
    }

    function proposeRotation() external {
        governor.execute(address(reserve), abi.encodeCall(reserve.proposeNotaries, (signers, 3)));
    }

    function rotate() external {
        try reserve.executeNotaries(signers, 3) {} catch {}
    }

    function cancelRotation() external {
        if (reserve.proposedNotariesHash() != bytes32(0)) {
            vm.prank(guardian);
            reserve.cancelNotariesProposal();
        }
    }

    function discard(uint256 index) external {
        if (requests.length == 0) return;
        USDOMReserve.Burn memory b = requests[index % requests.length];
        try reserve.discardWithdrawal(b.burnId) {} catch {}
        if (observedBurns[b.burnId]) assertTrue(reserve.paidBurns(b.burnId));
        if (observedRequests[b.requestId]) assertTrue(reserve.paidRequests(b.requestId));
    }

    function unauthorized(uint8 action) external {
        bytes memory data;
        if (action % 4 == 0) data = abi.encodeCall(reserve.pause, ());
        if (action % 4 == 1) data = abi.encodeCall(reserve.scheduleResume, ());
        if (action % 4 == 2) data = abi.encodeCall(reserve.proposeNotaries, (signers, 3));
        if (action % 4 == 3) data = abi.encodeCall(reserve.cancelNotariesProposal, ());
        (bool ok,) = address(reserve).call(data);
        assertFalse(ok);
    }

    function alteredSignature(uint64 raw) external {
        USDOMReserve.Burn memory b = makeBurn(uint64(uint256(raw) % reserve.outflowCapacity()) + 1);
        bytes[] memory sigs = sign(b);
        b.requestId = keccak256(abi.encode("altered request", ++nonce));
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.queueWithdrawal, (b, sigs)));
        assertFalse(ok);
    }

    function hostileTokenDeposit(uint8 raw) external {
        uint256 beforeCredit = reserve.totalDeposited();
        uint256 beforeBalance = token.balanceOf(address(reserve));
        token.mint(address(this), 100);
        token.setMode(HostileToken.Mode(2 + raw % 5));
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.deposit, (10, bytes32(++nonce), bytes32(uint256(1)))));
        assertFalse(ok);
        assertEq(reserve.totalDeposited(), beforeCredit);
        assertEq(token.balanceOf(address(reserve)), beforeBalance);
        token.setMode(HostileToken.Mode.Standard);
    }

    function expectedPending() external view returns (uint256 amount, uint256 count) {
        for (uint256 i; i < requests.length; ++i) {
            (bytes32 digest,,,, uint64 epoch,,,) = reserve.pendingWithdrawals(requests[i].burnId);
            if (digest != bytes32(0) && epoch == reserve.currentEpoch()) {
                amount += requests[i].amount;
                ++count;
            }
        }
    }

    function makeBurn(uint64 amount) private returns (USDOMReserve.Burn memory) {
        ++nonce;
        return USDOMReserve.Burn(
            keccak256(abi.encode("burn", nonce)),
            keccak256(abi.encode("request", nonce)),
            RECIPIENT,
            amount,
            reserve.domDomain(),
            uint64(nonce),
            keccak256(abi.encode("block", nonce)),
            reserve.currentEpoch(),
            uint64(block.timestamp + 6 days)
        );
    }

    function sign(USDOMReserve.Burn memory b) private view returns (bytes[] memory result) {
        result = new bytes[](3);
        bytes32 digest = reserve.burnDigest(b);
        for (uint256 i; i < 3; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            result[i] = abi.encodePacked(r, s, v);
        }
    }
}

contract USDOMReserveInvariantTest is ReserveFixture {
    ReserveHandler public handler;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function setUp() public override {
        super.setUp();
        handler = new ReserveHandler(reserve, token, governor, keys, signers);
        token.mint(address(handler), CAP * 10);
    }

    // Native Foundry targeting API; only attacker actions, never unrestricted mock setters.
    function targetContracts() public view returns (address[] memory result) {
        result = new address[](1);
        result[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory result) {
        bytes4[] memory selectors = new bytes4[](15);
        selectors[0] = handler.deposit.selector;
        selectors[1] = handler.queue.selector;
        selectors[2] = handler.execute.selector;
        selectors[3] = handler.advance.selector;
        selectors[4] = handler.donate.selector;
        selectors[5] = handler.pause.selector;
        selectors[6] = handler.scheduleResume.selector;
        selectors[7] = handler.resume.selector;
        selectors[8] = handler.proposeRotation.selector;
        selectors[9] = handler.rotate.selector;
        selectors[10] = handler.cancelRotation.selector;
        selectors[11] = handler.discard.selector;
        selectors[12] = handler.unauthorized.selector;
        selectors[13] = handler.alteredSignature.selector;
        selectors[14] = handler.hostileTokenDeposit.selector;
        result = new FuzzSelector[](1);
        result[0] = FuzzSelector(address(handler), selectors);
    }

    function invariantAccountingMatchesIndependentLedger() public view {
        assertEq(reserve.totalDeposited(), handler.ghostDeposited());
        assertEq(reserve.totalReleased(), handler.ghostPaid());
        assertEq(token.balanceOf(BOB), handler.ghostPaid());
        assertEq(
            token.balanceOf(address(reserve)) + handler.ghostPaid(), handler.ghostDeposited() + handler.ghostDonated()
        );
        assertTrue(reserve.totalReleased() <= reserve.totalDeposited());
        assertTrue(reserve.outstanding() <= CAP);
        assertTrue(token.balanceOf(address(reserve)) >= reserve.outstanding());
        assertTrue(reserve.availableOutflow() <= FLOW);
        (uint256 expectedAmount, uint256 expectedCount) = handler.expectedPending();
        assertEq(reserve.totalPendingAmount(), expectedAmount);
        assertEq(reserve.pendingCount(), expectedCount);
        bytes32 current = reserve.firstPendingBurn();
        bytes32 previous;
        uint256 linkedAmount;
        uint256 linkedCount;
        while (current != bytes32(0)) {
            (bytes32 digest, bytes32 requestId,,, uint64 epoch, uint64 amount, bytes32 prev, bytes32 next) =
                reserve.pendingWithdrawals(current);
            assertTrue(digest != bytes32(0));
            assertEq(epoch, reserve.currentEpoch());
            assertEq(prev, previous);
            assertEq(reserve.pendingRequests(requestId), current);
            assertFalse(reserve.paidBurns(current));
            assertFalse(reserve.paidRequests(requestId));
            linkedAmount += amount;
            ++linkedCount;
            assertTrue(linkedCount <= expectedCount); // detects cycles without an unbounded test loop
            previous = current;
            current = next;
        }
        assertEq(previous, reserve.lastPendingBurn());
        assertEq(linkedCount, expectedCount);
        assertEq(linkedAmount, expectedAmount);
        assertTrue(reserve.totalPendingAmount() <= reserve.outstanding());
        assertTrue(handler.ghostPaid() <= FLOW + (block.timestamp - handler.startTime()) * FLOW / 1 days);
        assertTrue(reserve.threshold() > uint256(reserve.notaryCount()) * 2 / 3);
    }
}
