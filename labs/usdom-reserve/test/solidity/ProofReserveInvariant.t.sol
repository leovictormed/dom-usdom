// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IDOMFinalizedBurnVerifier} from "../../contracts/IDOMFinalizedBurnVerifier.sol";
import {IDOMGracefulShutdownRegistry, USDOMProofReserve} from "../../contracts/USDOMProofReserve.sol";
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
    MockGracefulShutdownRegistry public immutable checkpointRegistry;
    USDOMProofReserve.FinalizedBurn[] private requests;
    uint256 private nonce;
    uint64 private pilotAmount;
    bytes32 private pilotSalt;
    bytes32 private pilotCommitment;

    uint256 public ghostDeposited;
    uint256 public ghostPaid;
    uint256 public ghostDonated;
    uint256 public ghostPending;
    uint256 public ghostPendingCount;
    uint256 public ghostProvedDebt;
    uint64 public highestPilotGeneration;
    bool public permissionlessOpenedAfterSettlement;
    uint256 public immutable startTime;
    mapping(bytes32 => bytes32) public ghostDebtHashes;
    mapping(bytes32 => uint64) public ghostFinalitySlots;
    mapping(bytes32 => bytes32) public ghostCurrentStatementHashes;

    constructor(
        USDOMProofReserve reserve_,
        HostileToken token_,
        MockGovernance governor_,
        MockGovernance guardian_,
        InvariantBurnVerifier burnVerifier_,
        MockGracefulShutdownRegistry checkpointRegistry_
    ) {
        reserve = reserve_;
        token = token_;
        governor = governor_;
        guardian = guardian_;
        burnVerifier = burnVerifier_;
        checkpointRegistry = checkpointRegistry_;
        ghostDeposited = reserve_.totalDeposited();
        startTime = block.timestamp;
    }

    function deposit(uint64 raw) external {
        if (!reserve.permissionlessDeposits() || reserve.depositsClosed()) return;
        uint256 room = reserve.maxOutstanding() - reserve.outstanding();
        if (room == 0 || reserve.paused()) return;
        // room <= maxOutstanding (uint64), so this narrowing conversion is safe.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 amount = uint64(uint256(raw) % room) + 1;
        if (token.balanceOf(address(this)) < amount) token.mint(address(this), amount);
        token.approve(address(reserve), amount);
        reserve.deposit(amount, keccak256(abi.encode("invariant deposit", ++nonce)), bytes32(uint256(1)));
        ghostDeposited += amount;
    }

    function authorizePilot(uint64 raw) external {
        if (
            reserve.paused() || reserve.depositsClosed() || reserve.permissionlessDeposits()
                || reserve.pilotDepositConsumed() || reserve.authorizedPilotDeposit() != bytes32(0)
                || reserve.totalDeposited() != 0
        ) return;
        uint64 amount = MIN_QUEUE_AMOUNT + raw % uint64(reserve.outflowCapacity() - MIN_QUEUE_AMOUNT + 1);
        bytes32 salt = keccak256(abi.encode("invariant pilot", ++nonce));
        bytes32 commitment = bytes32(uint256(1));
        uint256 deadline = block.timestamp + 1 days;
        if (deadline > type(uint64).max) return;
        uint64 validUntil = uint64(deadline);
        uint64 generation = reserve.pilotAuthorizationGeneration();
        governor.execute(
            address(reserve),
            abi.encodeCall(
                reserve.authorizePilotDeposit,
                (
                    keccak256(abi.encode("snapshot", nonce)),
                    address(this),
                    amount,
                    salt,
                    commitment,
                    validUntil,
                    generation
                )
            )
        );
        pilotAmount = amount;
        pilotSalt = salt;
        pilotCommitment = commitment;
        highestPilotGeneration = generation;
    }

    function consumePilot() external {
        if (reserve.paused() || reserve.authorizedPilotDeposit() == bytes32(0)) return;
        if (block.timestamp > reserve.authorizedPilotValidUntil()) {
            reserve.clearExpiredPilotDepositAuthorization(
                reserve.authorizedPilotSnapshot(), reserve.pilotAuthorizationGeneration()
            );
            highestPilotGeneration = reserve.pilotAuthorizationGeneration();
            return;
        }
        uint64 amount = pilotAmount;
        if (token.balanceOf(address(this)) < amount) token.mint(address(this), amount);
        token.approve(address(reserve), amount);
        reserve.deposit(amount, pilotSalt, pilotCommitment);
        ghostDeposited += amount;
        highestPilotGeneration = reserve.pilotAuthorizationGeneration();
    }

    function cancelPilot() external {
        bytes32 snapshot = reserve.authorizedPilotSnapshot();
        if (snapshot == bytes32(0)) return;
        uint64 generation = reserve.pilotAuthorizationGeneration();
        guardian.execute(
            address(reserve), abi.encodeCall(reserve.cancelPilotDepositAuthorization, (snapshot, generation))
        );
        highestPilotGeneration = reserve.pilotAuthorizationGeneration();
    }

    function clearExpiredPilot() external {
        bytes32 snapshot = reserve.authorizedPilotSnapshot();
        if (snapshot == bytes32(0)) return;
        uint64 generation = reserve.pilotAuthorizationGeneration();
        uint64 validUntil = reserve.authorizedPilotValidUntil();
        if (block.timestamp <= validUntil) vm.warp(uint256(validUntil) + 1);
        reserve.clearExpiredPilotDepositAuthorization(snapshot, generation);
        highestPilotGeneration = reserve.pilotAuthorizationGeneration();
    }

    function hostilePilotRollback(uint8 raw) external {
        if (reserve.paused() || reserve.authorizedPilotDeposit() == bytes32(0)) return;
        uint256 depositedBefore = reserve.totalDeposited();
        bytes32 authorizationBefore = reserve.authorizedPilotDeposit();
        bytes32 snapshotBefore = reserve.authorizedPilotSnapshot();
        uint64 deadlineBefore = reserve.authorizedPilotValidUntil();
        uint64 generationBefore = reserve.pilotAuthorizationGeneration();
        token.setMode(HostileToken.Mode(2 + raw % 5));
        token.approve(address(reserve), pilotAmount);
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.deposit, (pilotAmount, pilotSalt, pilotCommitment)));
        assertFalse(ok);
        assertEq(reserve.totalDeposited(), depositedBefore);
        assertEq(reserve.authorizedPilotDeposit(), authorizationBefore);
        assertEq(reserve.authorizedPilotSnapshot(), snapshotBefore);
        assertEq(reserve.authorizedPilotValidUntil(), deadlineBefore);
        assertEq(reserve.pilotAuthorizationGeneration(), generationBefore);
        token.setMode(HostileToken.Mode.Standard);
    }

    function openPermissionless() external {
        if (
            reserve.paused() || reserve.depositsClosed() || reserve.permissionlessDeposits()
                || !reserve.pilotDepositConsumed() || reserve.authorizedPilotDeposit() != bytes32(0)
                || reserve.authorizedPilotSnapshot() != bytes32(0) || reserve.authorizedPilotValidUntil() != 0
                || reserve.outstanding() != 0 || reserve.totalProvedDebtAmount() != 0
                || reserve.totalPendingAmount() != 0 || reserve.pendingCount() != 0
        ) return;
        if (reserve.permissionlessDepositsReadyAt() == 0) {
            governor.execute(address(reserve), abi.encodeCall(reserve.schedulePermissionlessDeposits, ()));
        }
        if (block.timestamp < reserve.permissionlessDepositsReadyAt()) {
            vm.warp(reserve.permissionlessDepositsReadyAt());
        }
        reserve.executePermissionlessDeposits();
        permissionlessOpenedAfterSettlement = true;
    }

    function closeDeposits() external {
        if (reserve.depositsClosed()) return;
        guardian.execute(address(reserve), abi.encodeCall(reserve.closeDeposits, ()));
        highestPilotGeneration = reserve.pilotAuthorizationGeneration();
        assertEq(reserve.authorizedPilotDeposit(), bytes32(0));
        assertEq(reserve.authorizedPilotSnapshot(), bytes32(0));
        assertEq(reserve.authorizedPilotValidUntil(), 0);
        assertEq(reserve.permissionlessDepositsReadyAt(), 0);
    }

    function finalizeShutdown() external {
        if (reserve.gracefullyShutdown() || !reserve.depositsClosed() || reserve.paused()) return;
        if (
            reserve.outstanding() != 0 || reserve.totalProvedDebtAmount() != 0 || reserve.pendingCount() != 0
                || reserve.totalPendingAmount() != 0 || reserve.firstPendingBurn() != bytes32(0)
                || reserve.lastPendingBurn() != bytes32(0) || reserve.authorizedPilotDeposit() != bytes32(0)
                || reserve.authorizedPilotSnapshot() != bytes32(0) || reserve.authorizedPilotValidUntil() != 0
                || reserve.permissionlessDepositsReadyAt() != 0
        ) return;
        uint128 settled = uint128(reserve.totalDeposited());
        checkpointRegistry.setTerminal(settled, settled, true, true);
        reserve.finalizeGracefulShutdown();
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
        ghostDebtHashes[b.burnId] = reserve.burnDebtHash(b);
        ghostFinalitySlots[b.burnId] = b.finalityBeaconSlot;
        ghostCurrentStatementHashes[b.burnId] = reserve.burnStatementHash(b);
        ghostPending += amount;
        ++ghostPendingCount;
        ghostProvedDebt += amount;
    }

    /// Renew an unpaid permanent debt after its queue lease expires or an
    /// emergency invalidates the generation. Only the finality slot may move;
    /// the independently recorded debt and aggregate obligation must not.
    function renew(uint256 index) external {
        if (requests.length == 0 || reserve.paused()) return;
        uint256 requestIndex = index % requests.length;
        USDOMProofReserve.FinalizedBurn memory b = requests[requestIndex];
        if (reserve.paidBurns(b.burnId)) return;

        (bytes32 statementHash,,, uint64 expiresAt, uint64 pendingEpoch,,,) = reserve.pendingWithdrawals(b.burnId);
        if (statementHash != bytes32(0)) {
            // forge-lint: disable-next-line(block-timestamp)
            if (pendingEpoch == reserve.queueEpoch() && block.timestamp <= expiresAt) return;
            reserve.discardWithdrawal(b.burnId);
            if (pendingEpoch == reserve.queueEpoch()) {
                ghostPending -= b.amount;
                --ghostPendingCount;
            }
        }

        bytes32 debtBefore = reserve.provedBurnDebts(b.burnId);
        uint256 aggregateBefore = reserve.totalProvedDebtAmount();
        b.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        bytes memory proof =
            canonicalRiscZeroProof(keccak256(abi.encode("invariant renewal", b.burnId, b.finalityBeaconSlot)));
        burnVerifier.approve(reserve.burnStatementHash(b), proof);
        reserve.queueWithdrawal(b, proof);

        assertEq(reserve.provedBurnDebts(b.burnId), debtBefore);
        assertEq(reserve.totalProvedDebtAmount(), aggregateBefore);
        requests[requestIndex] = b;
        ghostFinalitySlots[b.burnId] = b.finalityBeaconSlot;
        ghostCurrentStatementHashes[b.burnId] = reserve.burnStatementHash(b);
        ghostPending += b.amount;
        ++ghostPendingCount;
    }

    /// Recreate an expired or emergency-invalidated lease from the exact last
    /// statement already authenticated on-chain. This must remain live even
    /// when its historical finality slot has aged beyond the admission window.
    function replayExact(uint256 index) external {
        if (requests.length == 0 || reserve.paused()) return;
        uint256 requestIndex = index % requests.length;
        USDOMProofReserve.FinalizedBurn memory b = requests[requestIndex];
        if (reserve.paidBurns(b.burnId)) return;

        (bytes32 statementHash,,, uint64 expiresAt, uint64 pendingEpoch,,,) = reserve.pendingWithdrawals(b.burnId);
        if (statementHash != bytes32(0)) {
            // forge-lint: disable-next-line(block-timestamp)
            if (pendingEpoch == reserve.queueEpoch() && block.timestamp <= expiresAt) return;
            reserve.discardWithdrawal(b.burnId);
            if (pendingEpoch == reserve.queueEpoch()) {
                ghostPending -= b.amount;
                --ghostPendingCount;
            }
        }

        bytes32 debtBefore = reserve.provedBurnDebts(b.burnId);
        bytes32 latestBefore = reserve.latestProvedBurnStatements(b.burnId);
        uint64 slotBefore = reserve.provedBurnFinalitySlots(b.burnId);
        uint256 aggregateBefore = reserve.totalProvedDebtAmount();
        assertEq(latestBefore, reserve.burnStatementHash(b));
        reserve.queueWithdrawal(b, bytes(""));
        assertEq(reserve.provedBurnDebts(b.burnId), debtBefore);
        assertEq(reserve.latestProvedBurnStatements(b.burnId), latestBefore);
        assertEq(reserve.provedBurnFinalitySlots(b.burnId), slotBefore);
        assertEq(reserve.totalProvedDebtAmount(), aggregateBefore);
        ghostPending += b.amount;
        ++ghostPendingCount;
    }

    /// Even a proof accepted by the test verifier cannot substitute one field
    /// of an already established debt. This models a verifier/operator fault
    /// at the contract boundary and proves the local permanent binding holds.
    function attemptDebtSubstitution(uint256 index) external {
        if (requests.length == 0 || reserve.paused()) return;
        USDOMProofReserve.FinalizedBurn memory original = requests[index % requests.length];
        if (reserve.paidBurns(original.burnId)) return;
        USDOMProofReserve.FinalizedBurn memory changed = original;
        changed.height += 1;
        changed.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        bytes memory proof =
            canonicalRiscZeroProof(keccak256(abi.encode("invariant debt substitution", changed.burnId)));
        burnVerifier.approve(reserve.burnStatementHash(changed), proof);

        bytes32 debtBefore = reserve.provedBurnDebts(original.burnId);
        uint64 slotBefore = reserve.provedBurnFinalitySlots(original.burnId);
        uint256 aggregateBefore = reserve.totalProvedDebtAmount();
        (bool ok,) = address(reserve).call(abi.encodeCall(reserve.queueWithdrawal, (changed, proof)));
        assertFalse(ok);
        assertEq(reserve.provedBurnDebts(original.burnId), debtBefore);
        assertEq(reserve.provedBurnFinalitySlots(original.burnId), slotBefore);
        assertEq(reserve.totalProvedDebtAmount(), aggregateBefore);
    }

    function requestCount() external view returns (uint256) {
        return requests.length;
    }

    function requestAt(uint256 index) external view returns (USDOMProofReserve.FinalizedBurn memory) {
        return requests[index];
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
        if (reserve.gracefullyShutdown()) return;
        bool wasPaused = reserve.paused();
        guardian.execute(address(reserve), abi.encodeCall(reserve.pause, ()));
        highestPilotGeneration = reserve.pilotAuthorizationGeneration();
        if (!wasPaused) {
            ghostPending = 0;
            ghostPendingCount = 0;
        }
    }

    function scheduleResume() external {
        if (reserve.gracefullyShutdown()) return;
        if (reserve.paused()) governor.execute(address(reserve), abi.encodeCall(reserve.scheduleResume, ()));
    }

    function resume() external {
        if (reserve.gracefullyShutdown()) return;
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
                FLOW,
                true
            )
        );
        handler = new ProofReserveHandler(reserve, token, governor, guardian, burnVerifier, checkpointRegistry);
        token.mint(address(handler), CAP * 10);
    }

    function targetContracts() public view returns (address[] memory result) {
        result = new address[](1);
        result[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory result) {
        bytes4[] memory selectors = new bytes4[](24);
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
        selectors[13] = handler.renew.selector;
        selectors[14] = handler.attemptDebtSubstitution.selector;
        selectors[15] = handler.authorizePilot.selector;
        selectors[16] = handler.consumePilot.selector;
        selectors[17] = handler.cancelPilot.selector;
        selectors[18] = handler.clearExpiredPilot.selector;
        selectors[19] = handler.hostilePilotRollback.selector;
        selectors[20] = handler.openPermissionless.selector;
        selectors[21] = handler.closeDeposits.selector;
        selectors[22] = handler.finalizeShutdown.selector;
        selectors[23] = handler.replayExact.selector;
        result = new FuzzSelector[](1);
        result[0] = FuzzSelector(address(handler), selectors);
    }

    function invariantProofReserveMatchesIndependentLedgerAndQueue() public view {
        assertEq(reserve.totalDeposited(), handler.ghostDeposited());
        assertEq(reserve.totalReleased(), handler.ghostPaid());
        assertEq(reserve.totalReleased() + reserve.outstanding(), reserve.totalDeposited());
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
        assertEq(reserve.unreservedCollateral() + reserve.totalProvedDebtAmount(), reserve.outstanding());
        assertTrue(reserve.totalReleased() + reserve.totalPendingAmount() <= reserve.totalDeposited());
        assertTrue(reserve.totalReleased() + reserve.totalProvedDebtAmount() <= reserve.totalDeposited());
        assertTrue(token.balanceOf(address(reserve)) >= reserve.outstanding());
        assertTrue(reserve.availableOutflow() <= FLOW);
        bool authorizationSet = reserve.authorizedPilotDeposit() != bytes32(0);
        assertTrue(authorizationSet == (reserve.authorizedPilotSnapshot() != bytes32(0)));
        assertTrue(authorizationSet == (reserve.authorizedPilotValidUntil() != 0));
        assertTrue(reserve.pilotAuthorizationGeneration() >= handler.highestPilotGeneration());
        if (reserve.pilotDepositConsumed()) assertFalse(authorizationSet);
        if (reserve.permissionlessDeposits()) {
            assertTrue(reserve.pilotDepositConsumed());
            assertTrue(handler.permissionlessOpenedAfterSettlement());
            assertFalse(authorizationSet);
        }
        if (reserve.depositsClosed()) {
            assertFalse(authorizationSet);
            assertEq(reserve.permissionlessDepositsReadyAt(), 0);
        }
        if (reserve.gracefullyShutdown()) {
            assertTrue(reserve.depositsClosed());
            assertFalse(reserve.paused());
            assertEq(reserve.outstanding(), 0);
            assertEq(reserve.totalProvedDebtAmount(), 0);
            assertEq(reserve.pendingCount(), 0);
            assertEq(reserve.totalPendingAmount(), 0);
            assertFalse(authorizationSet);
        }

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
            // A renewal may legitimately advance only its finality slot, so
            // the active statement differs from the permanently retained first
            // statement while both remain bound to the same immutable debt.
            assertEq(statementHash, handler.ghostCurrentStatementHashes(current));
            assertTrue(reserve.provedBurnStatements(current) != bytes32(0));
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

        uint256 requestCount = handler.requestCount();
        for (uint256 i; i < requestCount; ++i) {
            USDOMProofReserve.FinalizedBurn memory b = handler.requestAt(i);
            assertEq(reserve.provedBurnDebts(b.burnId), handler.ghostDebtHashes(b.burnId));
            assertEq(reserve.provedRequestBurns(b.requestId), b.burnId);
            assertEq(reserve.provedBurnFinalitySlots(b.burnId), handler.ghostFinalitySlots(b.burnId));
            assertTrue(reserve.provedBurnStatements(b.burnId) != bytes32(0));
            assertEq(reserve.latestProvedBurnStatements(b.burnId), handler.ghostCurrentStatementHashes(b.burnId));
            if (reserve.paidBurns(b.burnId)) assertTrue(reserve.paidRequests(b.requestId));
        }
    }
}
