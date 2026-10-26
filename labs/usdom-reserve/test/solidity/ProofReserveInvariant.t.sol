// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    IDOMFinalizedBurnVerifier,
    IDOMGracefulShutdownRegistry,
    USDOMProofReserve
} from "../../contracts/USDOMProofReserve.sol";
import {HostileToken, MockGovernance, MockGracefulShutdownRegistry} from "./Mocks.sol";
import {TestBase} from "./TestBase.sol";

contract InvariantBurnVerifier is IDOMFinalizedBurnVerifier {
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 public constant CONFIG = keccak256("proof reserve invariant verifier");
    mapping(bytes32 => bool) private accepted;

    function verifierConfigHash() external pure returns (bytes32) {
        return CONFIG;
    }

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function verifyFinalizedBurn(bytes32 statementHash, bytes calldata proof) external view returns (bytes32) {
        return
            accepted[keccak256(abi.encode(statementHash, proof))]
                ? keccak256("USDOM_FINALIZED_BURN_PROOF_V1")
                : bytes32(0);
    }
}

contract ProofReserveHandler is TestBase {
    uint64 private constant MIN_QUEUE_AMOUNT = 1e6;
    address public constant RECIPIENT = address(0xB0B);

    USDOMProofReserve public immutable reserve;
    HostileToken public immutable token;
    MockGovernance public immutable governor;
    MockGovernance public immutable guardian;
    InvariantBurnVerifier public immutable burnVerifier;
    USDOMProofReserve.FinalizedBurn[] private requests;
    uint256 private nonce;

    uint256 public ghostDeposited;
    uint256 public ghostPaid;
    uint256 public ghostDonated;
    uint256 public ghostPending;
    uint256 public ghostPendingCount;
    uint256 public ghostProvedDebt;
    uint256 public immutable startTime;

    constructor(
        USDOMProofReserve reserve_,
        HostileToken token_,
        MockGovernance governor_,
        MockGovernance guardian_,
        InvariantBurnVerifier burnVerifier_
    ) {
        reserve = reserve_;
        token = token_;
        governor = governor_;
        guardian = guardian_;
        burnVerifier = burnVerifier_;
        ghostDeposited = reserve_.totalDeposited();
        startTime = block.timestamp;
        token_.approve(address(reserve_), type(uint256).max);
    }

    function deposit(uint64 raw) external {
        uint256 room = reserve.maxOutstanding() - reserve.outstanding();
        if (room == 0 || reserve.paused()) return;
        // room <= maxOutstanding (uint64), so this narrowing conversion is safe.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 amount = uint64(uint256(raw) % room) + 1;
        if (token.balanceOf(address(this)) < amount) token.mint(address(this), amount);
        reserve.deposit(amount, keccak256(abi.encode("invariant deposit", ++nonce)), bytes32(uint256(1)));
        ghostDeposited += amount;
    }

    function queue(uint64 raw) external {
        uint256 bound = reserve.unreservedCollateral();
        if (reserve.outflowCapacity() < bound) bound = reserve.outflowCapacity();
        if (bound < MIN_QUEUE_AMOUNT || reserve.paused()) return;
        uint256 range = bound - MIN_QUEUE_AMOUNT + 1;
        // bound <= outflowCapacity (uint64), so this narrowing conversion is safe.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 amount = MIN_QUEUE_AMOUNT + uint64(uint256(raw) % range);
        USDOMProofReserve.FinalizedBurn memory b = makeBurn(amount);
        bytes memory proof = canonicalRiscZeroProof(b.burnId);
        burnVerifier.approve(reserve.burnStatementHash(b), proof);
        reserve.queueWithdrawal(b, proof);
        requests.push(b);
        ghostPending += amount;
        ++ghostPendingCount;
        ghostProvedDebt += amount;
    }

    function execute(uint256 index) external {
        if (requests.length == 0) return;
        USDOMProofReserve.FinalizedBurn memory b = requests[index % requests.length];
        uint256 recipientBefore = token.balanceOf(RECIPIENT);
        uint256 releasedBefore = reserve.totalReleased();
        try reserve.executeWithdrawal(b) {
            ghostPaid += b.amount;
            ghostPending -= b.amount;
            --ghostPendingCount;
            ghostProvedDebt -= b.amount;
            assertEq(token.balanceOf(RECIPIENT), recipientBefore + b.amount);
        } catch {
            assertEq(token.balanceOf(RECIPIENT), recipientBefore);
            assertEq(reserve.totalReleased(), releasedBefore);
        }
    }

    function discard(uint256 index) external {
        if (requests.length == 0) return;
        USDOMProofReserve.FinalizedBurn memory b = requests[index % requests.length];
        (bytes32 statementHash,,,, uint64 pendingEpoch,,,) = reserve.pendingWithdrawals(b.burnId);
        if (statementHash == bytes32(0)) return;
        bool active = pendingEpoch == reserve.queueEpoch();
        try reserve.discardWithdrawal(b.burnId) {
            if (active) {
                ghostPending -= b.amount;
                --ghostPendingCount;
            }
        } catch {}
    }

    function pruneBatch(uint256 firstIndex, uint256 secondIndex) external {
        if (requests.length == 0) return;
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = requests[firstIndex % requests.length].burnId;
        ids[1] = requests[secondIndex % requests.length].burnId;
        uint256 expectedRemoved;
        for (uint256 i; i < ids.length; ++i) {
            if (i != 0 && ids[i] == ids[0]) continue;
            (bytes32 statementHash,,, uint64 expiresAt, uint64 pendingEpoch, uint64 amount,,) =
                reserve.pendingWithdrawals(ids[i]);
            // forge-lint: disable-next-line(block-timestamp)
            if (statementHash == bytes32(0) || (pendingEpoch == reserve.queueEpoch() && block.timestamp <= expiresAt)) {
                continue;
            }
            ++expectedRemoved;
            if (pendingEpoch == reserve.queueEpoch()) {
                ghostPending -= amount;
                --ghostPendingCount;
            }
        }
        assertEq(reserve.pruneDiscardable(ids), expectedRemoved);
    }

    function advance(uint32 seconds_) external {
        vm.warp(block.timestamp + uint256(seconds_) % 8 days);
    }

    function donate(uint64 raw) external {
        uint64 amount = raw % 1_000e6;
        token.mint(address(reserve), amount);
        ghostDonated += amount;
    }

    function pause() external {
        bool wasPaused = reserve.paused();
        guardian.execute(address(reserve), abi.encodeCall(reserve.pause, ()));
        if (!wasPaused) {
            ghostPending = 0;
            ghostPendingCount = 0;
        }
    }

    function scheduleResume() external {
        if (reserve.paused()) governor.execute(address(reserve), abi.encodeCall(reserve.scheduleResume, ()));
    }

    function resume() external {
        if (!reserve.paused()) return;
        if (reserve.resumeReadyAt() == 0) {
            governor.execute(address(reserve), abi.encodeCall(reserve.scheduleResume, ()));
        }
        if (block.timestamp < reserve.resumeReadyAt()) vm.warp(reserve.resumeReadyAt());
        reserve.executeResume();
    }

    function unauthorized(uint8 action) external {
        bytes memory data =
            action % 2 == 0 ? abi.encodeCall(reserve.pause, ()) : abi.encodeCall(reserve.scheduleResume, ());
        (bool ok,) = address(reserve).call(data);
        assertFalse(ok);
    }

    function alteredProof(uint64 raw) external {
        uint256 bound = reserve.unreservedCollateral();
        if (reserve.outflowCapacity() < bound) bound = reserve.outflowCapacity();
        if (bound == 0 || reserve.paused()) return;
        // bound <= outflowCapacity (uint64), so this narrowing conversion is safe.
        // forge-lint: disable-next-line(unsafe-typecast)
        USDOMProofReserve.FinalizedBurn memory b = makeBurn(uint64(uint256(raw) % bound) + 1);
        bytes memory proof = canonicalRiscZeroProof(keccak256(abi.encode("altered invariant proof", b.burnId)));
        burnVerifier.approve(reserve.burnStatementHash(b), proof);
        ++b.height;
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.queueWithdrawal, (b, proof)));
        assertFalse(ok);
    }

    function hostileTokenDeposit(uint8 raw) external {
        uint256 creditBefore = reserve.totalDeposited();
        uint256 balanceBefore = token.balanceOf(address(reserve));
        token.mint(address(this), 100);
        token.setMode(HostileToken.Mode(2 + raw % 5));
        (bool ok,) = address(reserve)
            .call(
                abi.encodeCall(
                    reserve.deposit,
                    (uint64(10), keccak256(abi.encode("hostile invariant deposit", ++nonce)), bytes32(uint256(1)))
                )
            );
        assertFalse(ok);
        assertEq(reserve.totalDeposited(), creditBefore);
        assertEq(token.balanceOf(address(reserve)), balanceBefore);
        token.setMode(HostileToken.Mode.Standard);
    }

    function makeBurn(uint64 amount) private returns (USDOMProofReserve.FinalizedBurn memory) {
        ++nonce;
        // nonce cannot approach uint64 in a bounded Foundry invariant campaign.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 height = uint64(nonce);
        return USDOMProofReserve.FinalizedBurn(
            keccak256(abi.encode("invariant burn", nonce)),
            keccak256(abi.encode("invariant request", nonce)),
            RECIPIENT,
            amount,
            reserve.domDomain(),
            height,
            keccak256(abi.encode("invariant DOM block", nonce)),
            keccak256(abi.encode("invariant USDOM state", nonce)),
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT()),
            uint64(block.timestamp + 6 days)
        );
    }
}

contract USDOMProofReserveInvariantTest is TestBase {
    uint64 private constant CAP = 100_000e6;
    uint64 private constant FLOW = 2_000e6;
    bytes32 private constant DOMAIN = keccak256("proof reserve invariant DOM domain");
    bytes32 private constant ACTIVATION_SCHEDULE = keccak256("proof reserve invariant activation schedule");

    HostileToken private token;
    MockGovernance private governor;
    MockGovernance private guardian;
    InvariantBurnVerifier private burnVerifier;
    USDOMProofReserve private reserve;
    ProofReserveHandler public handler;

    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        token = new HostileToken();
        governor = new MockGovernance();
        guardian = new MockGovernance();
        burnVerifier = new InvariantBurnVerifier();
        MockGracefulShutdownRegistry checkpointRegistry = new MockGracefulShutdownRegistry(DOMAIN, ACTIVATION_SCHEDULE);
        reserve = new USDOMProofReserve(
            USDOMProofReserve.Config(
                IERC20(address(token)),
                burnVerifier,
                IDOMGracefulShutdownRegistry(address(checkpointRegistry)),
                DOMAIN,
                ACTIVATION_SCHEDULE,
                address(governor),
                address(guardian),
                1 days,
                2 days,
                CAP,
                FLOW
            )
        );
        token.mint(address(this), 10_000e6);
        token.approve(address(reserve), 10_000e6);
        reserve.deposit(10_000e6, bytes32(uint256(1)), bytes32(uint256(1)));
        handler = new ProofReserveHandler(reserve, token, governor, guardian, burnVerifier);
        token.mint(address(handler), CAP * 10);
    }

    function targetContracts() public view returns (address[] memory result) {
        result = new address[](1);
        result[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory result) {
        bytes4[] memory selectors = new bytes4[](13);
        selectors[0] = handler.deposit.selector;
        selectors[1] = handler.queue.selector;
        selectors[2] = handler.execute.selector;
        selectors[3] = handler.discard.selector;
        selectors[4] = handler.advance.selector;
        selectors[5] = handler.donate.selector;
        selectors[6] = handler.pause.selector;
        selectors[7] = handler.scheduleResume.selector;
        selectors[8] = handler.resume.selector;
        selectors[9] = handler.alteredProof.selector;
        selectors[10] = handler.unauthorized.selector;
        selectors[11] = handler.hostileTokenDeposit.selector;
        selectors[12] = handler.pruneBatch.selector;
        result = new FuzzSelector[](1);
        result[0] = FuzzSelector(address(handler), selectors);
    }

    function invariantProofReserveMatchesIndependentLedgerAndQueue() public view {
        assertEq(reserve.totalDeposited(), handler.ghostDeposited());
        assertEq(reserve.totalReleased(), handler.ghostPaid());
        assertEq(token.balanceOf(handler.RECIPIENT()), handler.ghostPaid());
        assertEq(
            token.balanceOf(address(reserve)) + handler.ghostPaid(), handler.ghostDeposited() + handler.ghostDonated()
        );
        assertEq(reserve.totalPendingAmount(), handler.ghostPending());
        assertEq(reserve.pendingCount(), handler.ghostPendingCount());
        assertEq(reserve.totalProvedDebtAmount(), handler.ghostProvedDebt());
        assertTrue(reserve.totalReleased() <= reserve.totalDeposited());
        assertTrue(reserve.totalPendingAmount() <= reserve.outstanding());
        assertTrue(reserve.totalPendingAmount() <= reserve.totalProvedDebtAmount());
        assertTrue(reserve.totalProvedDebtAmount() <= reserve.outstanding());
        assertTrue(reserve.totalReleased() + reserve.totalPendingAmount() <= reserve.totalDeposited());
        assertTrue(reserve.totalReleased() + reserve.totalProvedDebtAmount() <= reserve.totalDeposited());
        assertTrue(token.balanceOf(address(reserve)) >= reserve.outstanding());
        assertTrue(reserve.availableOutflow() <= FLOW);

        bytes32 current = reserve.firstPendingBurn();
        bytes32 previous;
        uint256 linkedAmount;
        uint256 linkedCount;
        while (current != bytes32(0)) {
            (
                bytes32 statementHash,
                bytes32 requestId,,,
                uint64 pendingEpoch,
                uint64 amount,
                bytes32 prev,
                bytes32 next
            ) = reserve.pendingWithdrawals(current);
            assertTrue(statementHash != bytes32(0));
            assertEq(pendingEpoch, reserve.queueEpoch());
            assertEq(prev, previous);
            assertEq(reserve.pendingRequests(requestId), current);
            assertEq(reserve.provedBurnStatements(current), statementHash);
            assertEq(reserve.provedRequestBurns(requestId), current);
            assertFalse(reserve.paidBurns(current));
            assertFalse(reserve.paidRequests(requestId));
            linkedAmount += amount;
            ++linkedCount;
            assertTrue(linkedCount <= handler.ghostPendingCount());
            previous = current;
            current = next;
        }
        assertEq(previous, reserve.lastPendingBurn());
        assertEq(linkedCount, handler.ghostPendingCount());
        assertEq(linkedAmount, handler.ghostPending());
        assertTrue(handler.ghostPaid() <= FLOW + (block.timestamp - handler.startTime()) * FLOW / 1 days);
        assertEq(address(reserve.verifier()).codehash, reserve.verifierCodeHash());
        assertEq(address(reserve.token()).codehash, reserve.tokenCodeHash());
        assertEq(reserve.verifierConfigHash(), burnVerifier.CONFIG());
    }
}
