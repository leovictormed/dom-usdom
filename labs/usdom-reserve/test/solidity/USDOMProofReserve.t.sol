// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    IDOMFinalizedBurnVerifier,
    IDOMGracefulShutdownRegistry,
    USDOMProofReserve
} from "../../contracts/USDOMProofReserve.sol";
import {TestBase, Vm} from "./TestBase.sol";
import {HostileToken, MockGovernance, MockGracefulShutdownRegistry, MockMutableSingletonControl} from "./Mocks.sol";

contract MockFinalizedBurnVerifier is IDOMFinalizedBurnVerifier {
    bytes32 public PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 public override verifierConfigHash = keccak256("DOM verifier test configuration");
    mapping(bytes32 => bool) private accepted;

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function setConfigHash(bytes32 value) external {
        verifierConfigHash = value;
    }

    function setCapability(bytes32 value) external {
        PROOF_ACCEPTED = value;
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

contract CheckpointCapabilityOnBurnInterface is IDOMFinalizedBurnVerifier {
    bytes32 public constant PROOF_ACCEPTED = keccak256("DOM_CHECKPOINT_PROOF_V2");
    bytes32 public constant override verifierConfigHash = keccak256("wrong checkpoint capability");

    function verifyFinalizedBurn(bytes32, bytes calldata) external pure returns (bytes32) {
        return PROOF_ACCEPTED;
    }
}

contract MalformedBurnCapabilityVerifier is IDOMFinalizedBurnVerifier {
    enum Mode {
        RevertCall,
        ShortReturn,
        TrailingReturn,
        ReturnBomb
    }

    bytes32 public constant override verifierConfigHash = keccak256("malformed burn capability config");
    Mode public mode;

    function setMode(Mode value) external {
        mode = value;
    }

    function verifyFinalizedBurn(bytes32, bytes calldata) external pure returns (bytes32) {
        return keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    }

    fallback() external {
        if (mode == Mode.RevertCall) revert("capability revert");
        bytes32 accepted = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
        uint256 size = mode == Mode.ShortReturn ? 31 : mode == Mode.TrailingReturn ? 33 : 0x100000;
        assembly ("memory-safe") {
            mstore(0, accepted)
            return(0, size)
        }
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
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");

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
    bytes32 public constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");

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
    MockGracefulShutdownRegistry internal checkpointRegistry;
    USDOMProofReserve internal reserve;
    uint256 internal nonce;

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        token = new HostileToken();
        governor = new MockGovernance();
        guardian = new MockGovernance();
        burnVerifier = new MockFinalizedBurnVerifier();
        checkpointRegistry = new MockGracefulShutdownRegistry(DOMAIN, ACTIVATION_SCHEDULE);
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
            IDOMGracefulShutdownRegistry(address(checkpointRegistry)),
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
        return canonicalRiscZeroProof(b.burnId);
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
            bytes.concat(
                abi.encode(
                    reserve.RESERVE_IDENTITY_TYPEHASH(),
                    block.chainid,
                    address(reserve),
                    address(token),
                    address(token).codehash,
                    address(burnVerifier),
                    address(burnVerifier).codehash,
                    burnVerifier.verifierConfigHash()
                ),
                abi.encode(
                    address(checkpointRegistry),
                    address(checkpointRegistry).codehash,
                    checkpointRegistry.checkpointConfigHash(),
                    DOMAIN,
                    ACTIVATION_SCHEDULE
                )
            )
        );
        bytes32 policyHash = keccak256(
            abi.encode(
                reserve.RESERVE_POLICY_TYPEHASH(),
                keccak256(
                    abi.encode(
                        reserve.CONTROL_PLANE_IDENTITY_TYPEHASH(),
                        address(governor),
                        address(governor).codehash,
                        address(governor),
                        address(governor).codehash,
                        bytes32(0)
                    )
                ),
                keccak256(
                    abi.encode(
                        reserve.CONTROL_PLANE_IDENTITY_TYPEHASH(),
                        address(guardian),
                        address(guardian).codehash,
                        address(guardian),
                        address(guardian).codehash,
                        bytes32(0)
                    )
                ),
                uint64(1 days),
                uint64(2 days),
                CAP,
                FLOW
            )
        );
        bytes32 expected = keccak256(abi.encode(reserve.RESERVE_CONFIG_TYPEHASH(), identityHash, policyHash));
        assertEq(reserve.reserveConfigHash(), expected);
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

        c = config();
        c.verifier = IDOMFinalizedBurnVerifier(address(new CheckpointCapabilityOnBurnInterface()));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        MalformedBurnCapabilityVerifier malformed = new MalformedBurnCapabilityVerifier();
        for (uint256 i; i < 4; ++i) {
            malformed.setMode(MalformedBurnCapabilityVerifier.Mode(i));
            c = config();
            c.verifier = IDOMFinalizedBurnVerifier(address(malformed));
            vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
            new USDOMProofReserve(c);
        }
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

    function testDepositFailsClosedWhenCheckpointingOrNativeIssuanceStops() public {
        bytes32 salt = keccak256("halted checkpoint deposit");
        checkpointRegistry.setHalted(true);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.CheckpointingUnavailable.selector);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), INITIAL);
        checkpointRegistry.setHalted(false);

        checkpointRegistry.setTerminal(0, 0, true, false);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.CheckpointingUnavailable.selector);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), INITIAL);

        checkpointRegistry.setTerminal(0, 0, false, true);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.CheckpointingUnavailable.selector);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), INITIAL);

        checkpointRegistry.setTerminal(0, 0, false, false);
        vm.prank(ALICE);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), INITIAL + 1);
    }

    function testCheckpointHaltDoesNotBlockExistingProvedDebtPayout() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(1e6);
        checkpointRegistry.setHalted(true);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
    }

    function testRegistryIdentityDriftBlocksNewDebtButNotExistingDebtPayout() public {
        USDOMProofReserve.FinalizedBurn memory fresh = burn(1e6);
        bytes memory freshProof = proofFor(fresh);
        approve(fresh, freshProof);
        bytes32 originalConfig = checkpointRegistry.checkpointConfigHash();
        checkpointRegistry.setCheckpointConfigHash(keccak256("drifted checkpoint identity"));
        vm.expectRevert(USDOMProofReserve.RegistryChanged.selector);
        reserve.queueWithdrawal(fresh, freshProof);
        assertEq(reserve.totalProvedDebtAmount(), 0);

        checkpointRegistry.setCheckpointConfigHash(originalConfig);
        (USDOMProofReserve.FinalizedBurn memory established,) = queued(1e6);
        checkpointRegistry.setCheckpointConfigHash(keccak256("post-proof registry drift"));
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(established);
        assertTrue(reserve.paidBurns(established.burnId));
        assertEq(token.balanceOf(BOB), established.amount);
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

    function testFinalityExpiryAndBucketBoundaryEqualitiesRemainExecutable() public {
        uint64 currentSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        USDOMProofReserve.FinalizedBurn memory oldest = burn(FLOW);
        oldest.finalityBeaconSlot = currentSlot - uint64(reserve.MAX_FINALITY_AGE_SLOTS());
        bytes memory oldestProof = proofFor(oldest);
        approve(oldest, oldestProof);
        reserve.queueWithdrawal(oldest, oldestProof);
        (,, uint64 readyAt, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(oldest.burnId);
        assertEq(readyAt, block.timestamp + reserve.withdrawalDelay());
        assertEq(expiresAt, block.timestamp + reserve.MAX_CERTIFICATE_LIFETIME());

        // The lease is inclusive: execution is valid at the exact expiry,
        // while cleanup becomes valid only in the following timestamp.
        vm.warp(expiresAt);
        reserve.executeWithdrawal(oldest);
        assertEq(reserve.availableOutflow(), 0);

        (USDOMProofReserve.FinalizedBurn memory next,) = queued(FLOW);
        uint256 bucketStart = block.timestamp;
        vm.warp(bucketStart + reserve.REFILL_PERIOD() - 1);
        uint256 expected = (reserve.REFILL_PERIOD() - 1) * FLOW / reserve.REFILL_PERIOD();
        assertEq(reserve.availableOutflow(), expected);

        vm.warp(bucketStart + reserve.REFILL_PERIOD());
        assertEq(reserve.availableOutflow(), FLOW);
        reserve.executeWithdrawal(next);
        assertEq(reserve.availableOutflow(), 0);
        assertEq(reserve.totalReleased(), uint256(FLOW) * 2);
        assertEq(reserve.outstanding(), INITIAL - uint256(FLOW) * 2);
    }

    function testBeaconGenesisAndExactFirstNonzeroSlotFailClosedWithoutUnderflow() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(1);
        vm.warp(reserve.ETHEREUM_MAINNET_GENESIS_TIME() - 1);
        b.finalityBeaconSlot = 1;
        b.validUntil = uint64(block.timestamp + 6 days);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, proof);

        vm.warp(reserve.ETHEREUM_MAINNET_GENESIS_TIME() + reserve.ETHEREUM_SECONDS_PER_SLOT());
        b.finalityBeaconSlot = 1;
        b.validUntil = uint64(block.timestamp + 6 days);
        proof = proofFor(b);
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), 1);
        assertEq(reserve.pendingCount(), 1);
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

    function testProofReserveReentrancyCannotConsumeDepositOrBurnIdentifiers() public {
        bytes32 outerSalt = keccak256("outer proof deposit");
        bytes32 callbackSalt = keccak256("callback proof deposit");
        token.setCallback(
            address(reserve),
            abi.encodeCall(
                USDOMProofReserve.deposit,
                (uint64(1), callbackSalt, canonicalCommitment(keccak256("callback deposit commitment")))
            )
        );
        vm.prank(ALICE);
        reserve.deposit(100, outerSalt, canonicalCommitment(keccak256("outer deposit commitment")));
        assertFalse(token.callbackSucceeded());
        assertEq(reserve.totalDeposited(), INITIAL + 100);
        (address callbackFunder,,) = reserve.deposits(reserve.depositId(address(token), callbackSalt));
        assertEq(callbackFunder, address(0));

        token.setCallback(address(0), bytes(""));
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(100e6);
        USDOMProofReserve.FinalizedBurn memory callbackBurn = burn(100e6);
        bytes memory callbackProof = proofFor(callbackBurn);
        approve(callbackBurn, callbackProof);
        token.setCallback(
            address(reserve), abi.encodeCall(USDOMProofReserve.queueWithdrawal, (callbackBurn, callbackProof))
        );
        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(first);
        assertFalse(token.callbackSucceeded());
        assertEq(reserve.pendingRequests(callbackBurn.requestId), bytes32(0));
        assertEq(reserve.provedBurnStatements(callbackBurn.burnId), bytes32(0));
        assertEq(reserve.totalReleased(), first.amount);

        token.setCallback(address(0), bytes(""));
        reserve.queueWithdrawal(callbackBurn, callbackProof);
        assertEq(reserve.pendingRequests(callbackBurn.requestId), callbackBurn.burnId);
    }

    function testProofReserveFeeModesRollbackAndNoReturnUSDTStyleRemainsExact() public {
        for (uint256 i; i < 2; ++i) {
            token.setMode(i == 0 ? HostileToken.Mode.FeeOnTop : HostileToken.Mode.FeeOnReceive);
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
            reserve.deposit(
                100,
                keccak256(abi.encode("fee deposit", i)),
                canonicalCommitment(keccak256(abi.encode("fee commitment", i)))
            );
            assertEq(reserve.totalDeposited(), INITIAL);
            assertEq(token.balanceOf(address(reserve)), INITIAL);
        }

        token.setMode(HostileToken.Mode.NoReturn);
        vm.prank(ALICE);
        reserve.deposit(100, keccak256("no-return deposit"), canonicalCommitment(keccak256("no-return commitment")));
        assertEq(reserve.totalDeposited(), INITIAL + 100);

        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + 1 days);
        uint256 available = reserve.availableOutflow();
        for (uint256 i; i < 2; ++i) {
            token.setMode(i == 0 ? HostileToken.Mode.FeeOnTop : HostileToken.Mode.FeeOnReceive);
            vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
            reserve.executeWithdrawal(b);
            assertFalse(reserve.paidBurns(b.burnId));
            assertEq(reserve.totalReleased(), 0);
            assertEq(reserve.totalPendingAmount(), b.amount);
            assertEq(reserve.availableOutflow(), available);
        }

        token.setMode(HostileToken.Mode.NoReturn);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalReleased(), b.amount);
    }

    function testTokenReturnBombRollsBackDepositAndPayoutThenRetries() public {
        bytes32 salt = bytes32(uint256(0x661));
        bytes32 commitment = bytes32(uint256(0x662));
        uint256 aliceBefore = token.balanceOf(ALICE);
        token.setMode(HostileToken.Mode.ReturnBomb);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.deposit(1, salt, commitment);
        assertEq(token.balanceOf(ALICE), aliceBefore);
        assertEq(reserve.totalDeposited(), INITIAL);
        (address failedFunder,,) = reserve.deposits(reserve.depositId(ALICE, salt));
        assertEq(failedFunder, address(0));

        token.setMode(HostileToken.Mode.Standard);
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        uint256 availableBefore = reserve.availableOutflow();
        uint256 pendingBefore = reserve.totalPendingAmount();
        token.setMode(HostileToken.Mode.ReturnBomb);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalPendingAmount(), pendingBefore);
        assertEq(reserve.availableOutflow(), availableBefore);
        assertEq(token.balanceOf(BOB), 0);

        token.setMode(HostileToken.Mode.Standard);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
    }

    function testLifecycleLogsAreAtomicAndMatchFinalState() public {
        token.setMode(HostileToken.Mode.ReturnBomb);
        vm.recordLogs();
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.deposit(1, bytes32(uint256(0x6851)), bytes32(uint256(0x6852)));
        _assertNoReserveLogs(vm.getRecordedLogs());

        token.setMode(HostileToken.Mode.Standard);
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        token.setMode(HostileToken.Mode.ReturnBomb);
        vm.recordLogs();
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.executeWithdrawal(b);
        _assertNoReserveLogs(vm.getRecordedLogs());

        token.setMode(HostileToken.Mode.Standard);
        vm.recordLogs();
        reserve.executeWithdrawal(b);
        _assertReleasedLog(vm.getRecordedLogs(), b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertTrue(reserve.paidRequests(b.requestId));
        assertEq(reserve.totalReleased(), b.amount);
    }

    function testBalanceReturnBombCannotCreateCreditOrConsumeDebt() public {
        bytes32 salt = bytes32(uint256(0x663));
        token.setMode(HostileToken.Mode.BalanceReturnBomb);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.deposit(1, salt, bytes32(uint256(0x664)));
        token.setMode(HostileToken.Mode.Standard);
        assertEq(reserve.totalDeposited(), INITIAL);
        (address failedFunder,,) = reserve.deposits(reserve.depositId(ALICE, salt));
        assertEq(failedFunder, address(0));

        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        uint256 pendingBefore = reserve.totalPendingAmount();
        uint256 availableBefore = reserve.availableOutflow();
        token.setMode(HostileToken.Mode.BalanceReturnBomb);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.executeWithdrawal(b);
        token.setMode(HostileToken.Mode.Standard);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalPendingAmount(), pendingBefore);
        assertEq(reserve.availableOutflow(), availableBefore);
        assertEq(token.balanceOf(BOB), 0);

        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
    }

    function testShortTrailingAndGasGriefTransferResponsesFailAtomically() public {
        HostileToken.Mode[3] memory modes =
            [HostileToken.Mode.ShortReturn, HostileToken.Mode.TrailingReturn, HostileToken.Mode.GasGrief];
        for (uint256 i; i < modes.length; ++i) {
            bytes32 salt = bytes32(uint256(0x6650 + i));
            token.setMode(modes[i]);
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
            reserve.deposit(1, salt, bytes32(uint256(0x6660 + i)));
            token.setMode(HostileToken.Mode.Standard);
            assertEq(reserve.totalDeposited(), INITIAL);
            (address failedFunder,,) = reserve.deposits(reserve.depositId(ALICE, salt));
            assertEq(failedFunder, address(0));
        }

        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        uint256 pendingBefore = reserve.totalPendingAmount();
        uint256 availableBefore = reserve.availableOutflow();
        token.setMode(HostileToken.Mode.GasGrief);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        reserve.executeWithdrawal(b);
        token.setMode(HostileToken.Mode.Standard);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalPendingAmount(), pendingBefore);
        assertEq(reserve.availableOutflow(), availableBefore);
        assertEq(token.balanceOf(BOB), 0);

        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
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

    function testExpiredProvedDebtKeepsCollateralReservedUntilPayment() public {
        USDOMProofReserve.FinalizedBurn memory first;
        for (uint256 i; i < INITIAL / FLOW; ++i) {
            (USDOMProofReserve.FinalizedBurn memory proved,) = queued(FLOW);
            if (i == 0) first = proved;
            (,,, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(proved.burnId);
            vm.warp(expiresAt + 1);
            reserve.discardWithdrawal(proved.burnId);
        }

        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.totalProvedDebtAmount(), INITIAL);
        assertEq(reserve.unreservedCollateral(), 0);

        USDOMProofReserve.FinalizedBurn memory overcommitted = burn(1);
        bytes memory overcommittedProof = proofFor(overcommitted);
        approve(overcommitted, overcommittedProof);
        vm.expectRevert(USDOMProofReserve.Insolvent.selector);
        reserve.queueWithdrawal(overcommitted, overcommittedProof);

        first.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        bytes memory renewalProof = proofFor(first);
        approve(first, renewalProof);
        reserve.queueWithdrawal(first, renewalProof);
        assertEq(reserve.totalProvedDebtAmount(), INITIAL);
        assertEq(reserve.totalPendingAmount(), FLOW);

        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(first);
        assertEq(reserve.totalProvedDebtAmount(), INITIAL - FLOW);
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

    function testQueueSnapshotAndPaginationAreBoundedAndGenerationConsistent() public {
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(100e6);
        (USDOMProofReserve.FinalizedBurn memory middle,) = queued(200e6);
        (USDOMProofReserve.FinalizedBurn memory last,) = queued(300e6);

        (uint64 epoch, uint256 count, uint256 amount, bytes32 firstId, bytes32 lastId) = reserve.pendingQueueSnapshot();
        assertEq(epoch, reserve.queueEpoch());
        assertEq(count, 3);
        assertEq(amount, first.amount + middle.amount + last.amount);
        assertEq(firstId, first.burnId);
        assertEq(lastId, last.burnId);

        _assertQueuePages(epoch, first.burnId, middle.burnId, last.burnId);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 1);
        (uint64 newEpoch, uint256 newCount, uint256 newAmount, bytes32 newFirst, bytes32 newLast) =
            reserve.pendingQueueSnapshot();
        assertEq(newEpoch, epoch + 1);
        assertEq(newCount, 0);
        assertEq(newAmount, 0);
        assertEq(newFirst, bytes32(0));
        assertEq(newLast, bytes32(0));
        (bytes32[] memory emptyPage, bytes32 emptyCursor) =
            reserve.pendingBurnPage(newEpoch, bytes32(0), reserve.MAX_PRUNE_BATCH());
        assertEq(emptyPage.length, 0);
        assertEq(emptyCursor, bytes32(0));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(newEpoch, last.burnId, 1);
    }

    function testPaginationFailsClosedOnCyclesBrokenLinksHeadersAndCounts() public {
        // Keep permanent proved debt distinct from the active lease total so
        // bounded slot discovery fails on real layout ambiguity instead of
        // accidentally selecting the debt accumulator.
        (USDOMProofReserve.FinalizedBurn memory discarded,) = queued(1);
        (,,, uint64 discardedExpiry,,,,) = reserve.pendingWithdrawals(discarded.burnId);
        vm.warp(discardedExpiry + 1);
        reserve.discardWithdrawal(discarded.burnId);
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(100e6);
        (USDOMProofReserve.FinalizedBurn memory middle,) = queued(200e6);
        (USDOMProofReserve.FinalizedBurn memory last,) = queued(300e6);
        uint64 epoch = reserve.queueEpoch();
        bytes32 middleNextSlot = _pendingFieldSlot(middle.burnId, 4);
        bytes32 lastPreviousSlot = _pendingFieldSlot(last.burnId, 3);
        bytes32 pendingAmountSlot = _uniqueScalarSlot(bytes32(reserve.totalPendingAmount()));
        bytes32 pendingCountSlot = _uniqueScalarSlot(bytes32(reserve.pendingCount()));
        bytes32 firstPendingSlot = _uniqueScalarSlot(reserve.firstPendingBurn());
        bytes32 lastPendingSlot = _uniqueScalarSlot(reserve.lastPendingBurn());

        vm.store(address(reserve), middleNextSlot, first.burnId);
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 256);
        vm.store(address(reserve), middleNextSlot, last.burnId);

        vm.store(address(reserve), lastPreviousSlot, first.burnId);
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, middle.burnId, 2);
        vm.store(address(reserve), lastPreviousSlot, middle.burnId);

        vm.store(address(reserve), pendingCountSlot, bytes32(uint256(4)));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 256);
        vm.store(address(reserve), pendingCountSlot, bytes32(uint256(2)));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 2);
        vm.store(address(reserve), pendingCountSlot, bytes32(uint256(3)));

        vm.store(address(reserve), firstPendingSlot, bytes32(0));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 1);
        vm.store(address(reserve), firstPendingSlot, first.burnId);
        vm.store(address(reserve), lastPendingSlot, bytes32(0));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 1);
        vm.store(address(reserve), lastPendingSlot, last.burnId);
        vm.store(address(reserve), pendingAmountSlot, bytes32(0));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 1);

        // Storage corruption in this test is deliberate; the valid baseline
        // was already exercised before each independent mutation.
        assertEq(reserve.pendingCount(), 3);
    }

    function testPruningRejectsGenerationCorruptionStillReferencedByCurrentQueue() public {
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(100e6);
        (USDOMProofReserve.FinalizedBurn memory middle,) = queued(200e6);
        queued(300e6);
        (,,, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(first.burnId);
        vm.warp(expiresAt + 1);

        bytes32 firstPackedSlot = _pendingFieldSlot(first.burnId, 2);
        bytes32 firstPacked = vm.load(address(reserve), firstPackedSlot);
        vm.store(address(reserve), firstPackedSlot, _withQueueEpoch(firstPacked, reserve.queueEpoch() + 1));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pruneExpired(1);
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.discardWithdrawal(first.burnId);
        vm.store(address(reserve), firstPackedSlot, firstPacked);

        bytes32 middlePackedSlot = _pendingFieldSlot(middle.burnId, 2);
        bytes32 middlePacked = vm.load(address(reserve), middlePackedSlot);
        vm.store(address(reserve), middlePackedSlot, _withQueueEpoch(middlePacked, reserve.queueEpoch() + 1));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.discardWithdrawal(middle.burnId);
        vm.store(address(reserve), middlePackedSlot, middlePacked);

        assertEq(reserve.pruneExpired(3), 3);
        assertEq(reserve.pendingCount(), 0);
        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.totalProvedDebtAmount(), 600e6);
    }

    function testOldEpochCleanupCannotEraseExactRenewalOrCorruptMixedQueue() public {
        (USDOMProofReserve.FinalizedBurn memory first, bytes memory firstProof) = queued(100e6);
        (USDOMProofReserve.FinalizedBurn memory middle, bytes memory middleProof) = queued(200e6);
        (USDOMProofReserve.FinalizedBurn memory last, bytes memory lastProof) = queued(300e6);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertEq(reserve.pendingCount(), 0);
        assertEq(reserve.totalPendingAmount(), 0);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(block.timestamp + 2 days);
        reserve.executeResume();

        // Renewing an exact debt overwrites its old-epoch storage slot and
        // appends that identifier to the current queue generation.
        middle.finalityBeaconSlot = _currentBeaconSlot();
        middleProof = proofFor(middle);
        approve(middle, middleProof);
        reserve.queueWithdrawal(middle, middleProof);
        (USDOMProofReserve.FinalizedBurn memory current,) = queued(400e6);

        bytes32[] memory candidates = new bytes32[](6);
        candidates[0] = first.burnId;
        candidates[1] = middle.burnId;
        candidates[2] = last.burnId;
        candidates[3] = first.burnId;
        candidates[4] = current.burnId;
        candidates[5] = keccak256("unknown old-epoch burn");
        assertEq(reserve.pruneDiscardable(candidates), 2);

        assertEq(reserve.pendingCount(), 2);
        assertEq(reserve.totalPendingAmount(), middle.amount + current.amount);
        assertEq(reserve.firstPendingBurn(), middle.burnId);
        assertEq(reserve.lastPendingBurn(), current.burnId);
        (,,,,,, bytes32 middlePrevious, bytes32 middleNext) = reserve.pendingWithdrawals(middle.burnId);
        (,,,,,, bytes32 currentPrevious, bytes32 currentNext) = reserve.pendingWithdrawals(current.burnId);
        assertEq(middlePrevious, bytes32(0));
        assertEq(middleNext, current.burnId);
        assertEq(currentPrevious, middle.burnId);
        assertEq(currentNext, bytes32(0));
        assertEq(reserve.pendingRequests(first.requestId), bytes32(0));
        assertEq(reserve.pendingRequests(last.requestId), bytes32(0));
        assertEq(reserve.pendingRequests(middle.requestId), middle.burnId);
        assertEq(reserve.provedBurnStatements(first.burnId), reserve.burnStatementHash(first));
        assertEq(reserve.provedRequestBurns(last.requestId), last.burnId);

        // A pruned old debt can itself renew without disturbing the live list.
        first.finalityBeaconSlot = _currentBeaconSlot();
        firstProof = proofFor(first);
        approve(first, firstProof);
        reserve.queueWithdrawal(first, firstProof);
        assertEq(reserve.pendingCount(), 3);
        assertEq(reserve.totalPendingAmount(), first.amount + middle.amount + current.amount);
        assertEq(reserve.lastPendingBurn(), first.burnId);
        assertEq(reserve.pruneDiscardable(candidates), 0);

        (,,, uint64 queueExpiry,,,,) = reserve.pendingWithdrawals(middle.burnId);
        vm.warp(queueExpiry + 1);
        reserve.discardWithdrawal(current.burnId);
        assertEq(reserve.pendingCount(), 2);
        assertEq(reserve.totalPendingAmount(), first.amount + middle.amount);
        assertEq(reserve.pruneExpired(2), 2);
        assertEq(reserve.pendingCount(), 0);
        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.firstPendingBurn(), bytes32(0));
        assertEq(reserve.lastPendingBurn(), bytes32(0));

        // Even after both epoch invalidation and expiry cleanup, the third
        // finalized debt remains renewable only as its exact proved statement.
        last.finalityBeaconSlot = _currentBeaconSlot();
        lastProof = proofFor(last);
        approve(last, lastProof);
        reserve.queueWithdrawal(last, lastProof);
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), last.amount);
        assertEq(reserve.firstPendingBurn(), last.burnId);
        assertEq(reserve.lastPendingBurn(), last.burnId);
        assertEq(reserve.pendingRequests(last.requestId), last.burnId);
    }

    function testMaximumBatchPruneIsExecutableAfterEmergencyInvalidation() public {
        bytes32[] memory candidates = new bytes32[](256);
        for (uint256 i; i < candidates.length; ++i) {
            (USDOMProofReserve.FinalizedBurn memory pending,) = queued(1);
            candidates[i] = pending.burnId;
        }
        assertEq(reserve.pendingCount(), candidates.length);
        uint256 paginationGasBefore = gasleft();
        (bytes32[] memory page, bytes32 nextCursor) =
            reserve.pendingBurnPage(reserve.queueEpoch(), bytes32(0), candidates.length);
        uint256 paginationGas = paginationGasBefore - gasleft();
        assertTrue(paginationGas < 10_000_000);
        assertEq(page.length, candidates.length);
        assertEq(page[0], candidates[0]);
        assertEq(page[page.length - 1], candidates[candidates.length - 1]);
        assertEq(nextCursor, bytes32(0));
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
        other.queueWithdrawal(b, canonicalRiscZeroProof(bytes32(uint256(1))));
        assertEq(other.totalPendingAmount(), 0);
    }

    function testLegacyUsdtUpgradeTargetFailsClosedWithoutConsumingDepositId() public {
        bytes32 salt = keccak256("legacy USDT upgrade target");
        bytes32 depositIdentifier = reserve.depositId(ALICE, salt);
        token.setUpgradedAddress(address(0x1234));
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.UnsafeTokenState.selector);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        (address funder,,) = reserve.deposits(depositIdentifier);
        assertEq(funder, address(0));
        token.setUpgradedAddress(address(0));
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
        other.queueWithdrawal(b, canonicalRiscZeroProof(bytes32(uint256(1))));
        assertEq(other.totalPendingAmount(), 0);
    }

    function testFrozenFunderIsRejectedButFrozenRecipientDebtIsReserved() public {
        token.setBlocked(ALICE);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(USDOMProofReserve.FrozenTokenAccount.selector, ALICE));
        reserve.deposit(1, bytes32(uint256(81)), bytes32(uint256(82)));
        token.setBlocked(BOB);
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), b.amount);
        assertEq(reserve.totalProvedDebtAmount(), b.amount);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        vm.expectRevert(abi.encodeWithSelector(USDOMProofReserve.FrozenTokenAccount.selector, BOB));
        reserve.executeWithdrawal(b);
        assertEq(reserve.totalPendingAmount(), b.amount);
        assertEq(reserve.totalProvedDebtAmount(), b.amount);
        token.setBlocked(address(0));
        reserve.executeWithdrawal(b);
        assertEq(reserve.totalProvedDebtAmount(), 0);
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
        assertEq(reserve.SAFE_MAINNET_SINGLETON(), 0x41675C099F32341bf84BFc5382aF534df5C7461a);
        assertEq(
            reserve.SAFE_MAINNET_SINGLETON_CODE_HASH(),
            0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4
        );
        assertEq(
            reserve.SAFE_MAINNET_PROXY_CODE_HASH(),
            0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c
        );
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        safeGovernance.setFallbackHandler(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        safeGuardian.setFallbackHandler(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        installMainnetSafeFallbackHandler();
        vm.chainId(1);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
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

    function testConstructorRejectsCheckpointRegistryRoleOverlap() public {
        USDOMProofReserve.Config memory c = config();
        c.governance = address(c.checkpointRegistry);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        c = config();
        c.guardian = address(c.checkpointRegistry);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
    }

    function testConstructorRejectsEOAAndPrecompileTokenDespiteEmptyCallSuccess() public {
        USDOMProofReserve.Config memory c = config();
        c.token = IERC20(ALICE);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        c = config();
        c.token = IERC20(address(1));
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
        (bytes32 pendingStatement,,,,,,,) = reserve.pendingWithdrawals(b.burnId);
        assertEq(pendingStatement, bytes32(0));
        assertEq(reserve.pendingRequests(b.requestId), bytes32(0));
        assertEq(reserve.provedBurnStatements(b.burnId), reserve.burnStatementHash(b));
        assertEq(reserve.provedRequestBurns(b.requestId), b.burnId);
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

        b.burnId = keccak256("other burn id");
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.requestId = keccak256("other request id");
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.recipient = ALICE;
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.amount += 1;
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.domDomain = keccak256("other statement domain");
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.height += 1;
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.blockHash = keccak256("other statement block");
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.stateRoot = keccak256("other private state");
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.finalityBeaconSlot += 1;
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);
        b.validUntil += 1;
        assertTrue(original != reserve.burnStatementHash(b));
        b = burn(100e6);

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

    function testProofCannotReplayAcrossReserveDomainOrActivationDeployment() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        bytes32 authorizedStatement = reserve.burnStatementHash(b);
        bytes32 authorizedIntent = reserve.burnIntentHash(b);
        approve(b, proof);

        USDOMProofReserve.Config memory otherConfig = config();
        otherConfig.activationScheduleCommitment = keccak256("other activation schedule");
        otherConfig.checkpointRegistry = IDOMGracefulShutdownRegistry(
            address(new MockGracefulShutdownRegistry(DOMAIN, otherConfig.activationScheduleCommitment))
        );
        USDOMProofReserve otherActivation = new USDOMProofReserve(otherConfig);
        assertTrue(otherActivation.reserveConfigHash() != reserve.reserveConfigHash());
        assertTrue(otherActivation.burnStatementHash(b) != authorizedStatement);
        assertTrue(otherActivation.burnIntentHash(b) != authorizedIntent);
        vm.startPrank(ALICE);
        token.approve(address(otherActivation), INITIAL);
        otherActivation.deposit(
            INITIAL, bytes32(uint256(0xA1)), canonicalCommitment(keccak256("other activation output"))
        );
        vm.stopPrank();
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        otherActivation.queueWithdrawal(b, proof);

        otherConfig = config();
        otherConfig.domDomain = keccak256("other DOM domain");
        otherConfig.checkpointRegistry = IDOMGracefulShutdownRegistry(
            address(new MockGracefulShutdownRegistry(otherConfig.domDomain, ACTIVATION_SCHEDULE))
        );
        USDOMProofReserve otherDomain = new USDOMProofReserve(otherConfig);
        USDOMProofReserve.FinalizedBurn memory otherBurn = b;
        otherBurn.domDomain = otherConfig.domDomain;
        assertTrue(otherDomain.reserveConfigHash() != reserve.reserveConfigHash());
        assertTrue(otherDomain.burnStatementHash(otherBurn) != authorizedStatement);
        assertTrue(otherDomain.burnIntentHash(otherBurn) != authorizedIntent);
        vm.startPrank(ALICE);
        token.approve(address(otherDomain), INITIAL);
        otherDomain.deposit(INITIAL, bytes32(uint256(0xD1)), canonicalCommitment(keccak256("other domain output")));
        vm.stopPrank();
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        otherDomain.queueWithdrawal(otherBurn, proof);

        // The original proof remains valid only at its exact reserve/domain/
        // activation tuple, so failed replay attempts consume no identifier.
        // Memory-struct assignment aliases in Solidity; restore the field
        // changed through `otherBurn` before exercising the original tuple.
        b.domDomain = DOMAIN;
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.pendingRequests(b.requestId), b.burnId);
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

    function testSharedBurnEncoderMatchesCanonicalAbiEncoding() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        assertEq(
            reserve.burnStatementHash(b),
            keccak256(
                abi.encode(
                    reserve.BURN_STATEMENT_TYPEHASH(),
                    b.burnId,
                    b.requestId,
                    b.recipient,
                    b.amount,
                    b.domDomain,
                    b.height,
                    b.blockHash,
                    b.stateRoot,
                    b.finalityBeaconSlot,
                    b.validUntil,
                    block.chainid,
                    address(reserve),
                    reserve.activationScheduleCommitment()
                )
            )
        );
        assertEq(
            reserve.burnDebtHash(b),
            keccak256(
                abi.encode(
                    reserve.BURN_DEBT_TYPEHASH(),
                    b.burnId,
                    b.requestId,
                    b.recipient,
                    b.amount,
                    b.domDomain,
                    b.height,
                    b.blockHash,
                    b.stateRoot,
                    b.validUntil,
                    block.chainid,
                    address(reserve),
                    reserve.activationScheduleCommitment()
                )
            )
        );
        assertEq(
            reserve.burnIntentHash(b),
            keccak256(
                abi.encode(
                    reserve.BURN_INTENT_TYPEHASH(),
                    b.burnId,
                    b.requestId,
                    b.recipient,
                    b.amount,
                    b.domDomain,
                    b.validUntil,
                    block.chainid,
                    address(reserve)
                )
            )
        );
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

    function testMutableVerifierCapabilityFailsClosedAndCanRecoverBeforeValueMoves() public {
        burnVerifier.setCapability(keccak256("DOM_CHECKPOINT_PROOF_V2"));
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.deposit(1, bytes32(uint256(0x6461)), bytes32(uint256(0x6462)));
        assertEq(reserve.totalDeposited(), INITIAL);

        burnVerifier.setCapability(reserve.PROOF_ACCEPTED());
        vm.prank(ALICE);
        reserve.deposit(1, bytes32(uint256(0x6461)), bytes32(uint256(0x6462)));
        assertEq(reserve.totalDeposited(), INITIAL + 1);
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

    function testSafeSingletonIdentityIsImmutableAcrossValuePaths() public {
        MockGovernance implementation = new MockGovernance();
        MockGovernance replacement = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);
        USDOMProofReserve protectedReserve = new USDOMProofReserve(c);

        assertEq(protectedReserve.governanceImplementation(), address(implementation));
        assertEq(protectedReserve.governanceImplementationCodeHash(), address(implementation).codehash);
        assertEq(protectedReserve.guardianImplementation(), address(implementation));
        safeGovernance.setMasterCopy(address(replacement));

        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(901)), bytes32(uint256(902)));
    }

    function testSafeOwnerCommitmentBindsConfigAndRuntimeDespiteIdenticalInitcode() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);

        bytes32 initcodeHashBefore = keccak256(abi.encodePacked(type(USDOMProofReserve).creationCode, abi.encode(c)));
        USDOMProofReserve first = new USDOMProofReserve(c);
        bytes32 firstOwners = first.governanceOwnersCommitment();
        bytes32 firstIdentity = keccak256(
            abi.encode(
                first.CONTROL_PLANE_IDENTITY_TYPEHASH(),
                address(safeGovernance),
                address(safeGovernance).codehash,
                address(implementation),
                address(implementation).codehash,
                firstOwners
            )
        );

        safeGovernance.setOwner(0, address(0x104));
        bytes32 initcodeHashAfter = keccak256(abi.encodePacked(type(USDOMProofReserve).creationCode, abi.encode(c)));
        USDOMProofReserve second = new USDOMProofReserve(c);
        bytes32 secondOwners = second.governanceOwnersCommitment();
        bytes32 secondIdentity = keccak256(
            abi.encode(
                second.CONTROL_PLANE_IDENTITY_TYPEHASH(),
                address(safeGovernance),
                address(safeGovernance).codehash,
                address(implementation),
                address(implementation).codehash,
                secondOwners
            )
        );

        assertEq(initcodeHashBefore, initcodeHashAfter);
        assertTrue(firstOwners != secondOwners);
        assertTrue(firstIdentity != secondIdentity);
        assertTrue(first.reserveConfigHash() != second.reserveConfigHash());
        assertTrue(address(first).codehash != address(second).codehash);
    }

    function testSafePolicyDriftFailsClosedAcrossValuePaths() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);
        USDOMProofReserve protectedReserve = new USDOMProofReserve(c);
        vm.prank(ALICE);
        token.approve(address(protectedReserve), type(uint256).max);
        assertTrue(protectedReserve.controlPlaneHealthy());
        assertEq(
            protectedReserve.governanceOwnersCommitment(),
            keccak256(abi.encode(address(0x101), address(0x102), address(0x103)))
        );
        assertEq(protectedReserve.guardianOwnersCommitment(), protectedReserve.governanceOwnersCommitment());

        // Replacing one owner with another distinct EOA preserves 2-of-3 and
        // every old shape check. The immutable ordered commitment must still
        // stop value movement until the deployed owner set is restored.
        safeGovernance.setOwner(0, address(0x104));
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(9011)), bytes32(uint256(9012)));
        safeGovernance.setOwner(0, address(0x101));
        assertTrue(protectedReserve.controlPlaneHealthy());

        // Safe's linked-list order may change after remove/re-add without
        // changing the 2-of-3 authority. Canonical set identity preserves liveness.
        safeGovernance.setOwner(0, address(0x102));
        safeGovernance.setOwner(1, address(0x101));
        assertTrue(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        protectedReserve.deposit(1, bytes32(uint256(0x1004)), bytes32(uint256(0x1005)));
        safeGovernance.setOwner(0, address(0x101));
        safeGovernance.setOwner(1, address(0x102));
        assertTrue(protectedReserve.controlPlaneHealthy());

        safeGovernance.setThreshold(1);
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(903)), bytes32(uint256(904)));

        safeGovernance.setThreshold(2);
        safeGuardian.setOwnerCount(2);
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(905)), bytes32(uint256(906)));

        safeGuardian.setOwnerCount(3);
        safeGuardian.setOwner(2, address(0x103));
        safeGovernance.setModule(address(0xBEEF));
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(907)), bytes32(uint256(908)));

        safeGovernance.setModule(address(0));
        safeGovernance.setOwner(1, address(implementation));
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(909)), bytes32(uint256(910)));

        safeGovernance.setOwner(1, address(0x102));
        safeGuardian.setGuard(address(0xBEEF));
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(911)), bytes32(uint256(912)));

        safeGuardian.setGuard(address(0));
        vm.chainId(1);
        assertFalse(protectedReserve.controlPlaneHealthy());
        safeGovernance.setFallbackHandler(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        safeGuardian.setFallbackHandler(0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99);
        assertFalse(protectedReserve.controlPlaneHealthy());
        installMainnetSafeFallbackHandler();
        assertTrue(protectedReserve.controlPlaneHealthy());
        vm.etch(SAFE_MAINNET_FALLBACK_HANDLER, hex"00");
        assertFalse(protectedReserve.controlPlaneHealthy());
        installMainnetSafeFallbackHandler();
        safeGuardian.setFallbackHandler(address(0xBEEF));
        assertFalse(protectedReserve.controlPlaneHealthy());
    }

    function testSafeDriftBetweenQueueExecuteAndResumePreservesRetryableState() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);
        USDOMProofReserve protectedReserve = new USDOMProofReserve(c);

        vm.startPrank(ALICE);
        token.approve(address(protectedReserve), INITIAL);
        protectedReserve.deposit(
            INITIAL, keccak256("safe TOCTOU deposit"), canonicalCommitment(keccak256("safe TOCTOU commitment"))
        );
        vm.stopPrank();

        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        burnVerifier.approve(protectedReserve.burnStatementHash(b), proof);
        protectedReserve.queueWithdrawal(b, proof);
        vm.warp(block.timestamp + 1 days);
        uint256 availableBefore = protectedReserve.availableOutflow();

        safeGovernance.setOwner(0, address(0x104));
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.executeWithdrawal(b);
        assertFalse(protectedReserve.paidBurns(b.burnId));
        assertEq(protectedReserve.totalPendingAmount(), b.amount);
        assertEq(protectedReserve.availableOutflow(), availableBefore);

        safeGovernance.setOwner(0, address(0x101));
        safeGuardian.setModule(address(0xBEEF));
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.executeWithdrawal(b);
        assertFalse(protectedReserve.paidBurns(b.burnId));
        assertEq(protectedReserve.totalReleased(), 0);

        safeGuardian.setModule(address(0));
        protectedReserve.executeWithdrawal(b);
        assertTrue(protectedReserve.paidBurns(b.burnId));

        safeGuardian.execute(address(protectedReserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        safeGovernance.setGuard(address(0xBEEF));
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        safeGovernance.execute(address(protectedReserve), abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        assertEq(protectedReserve.resumeReadyAt(), 0);

        safeGovernance.setGuard(address(0));
        safeGovernance.execute(address(protectedReserve), abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        uint64 scheduled = protectedReserve.resumeReadyAt();
        safeGuardian.setOwner(2, address(0x104));
        vm.warp(scheduled);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.executeResume();
        assertTrue(protectedReserve.paused());
        assertEq(protectedReserve.resumeReadyAt(), scheduled);

        safeGuardian.setOwner(2, address(0x103));
        protectedReserve.executeResume();
        assertFalse(protectedReserve.paused());
        assertEq(protectedReserve.resumeReadyAt(), 0);
    }

    function testConstructorRejectsUnsafeSafePolicy() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);

        safeGovernance.setThreshold(1);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        safeGovernance.setThreshold(2);
        safeGovernance.setOwnerCount(4);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        safeGovernance.setOwnerCount(3);
        safeGovernance.setModule(address(0xBEEF));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        safeGovernance.setModule(address(0));
        safeGovernance.setOwner(1, address(implementation));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        safeGovernance.setOwner(1, address(0x102));
        safeGovernance.setGuard(address(0xBEEF));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
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

    function testDepositShutdownDoesNotBlockExistingBurnPayouts() public {
        (USDOMProofReserve.FinalizedBurn memory existingBurn,) = queued(100e6);

        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.Unauthorized.selector);
        reserve.closeDeposits();
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        assertTrue(reserve.depositsClosed());

        vm.expectRevert(USDOMProofReserve.DepositsClosed.selector);
        reserve.deposit(1, bytes32(uint256(3)), bytes32(uint256(4)));
        vm.expectRevert(USDOMProofReserve.DepositsClosed.selector);
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));

        USDOMProofReserve.FinalizedBurn memory newDebt = burn(1);
        bytes memory newDebtProof = proofFor(newDebt);
        approve(newDebt, newDebtProof);
        vm.expectRevert(USDOMProofReserve.DepositsClosed.selector);
        reserve.queueWithdrawal(newDebt, newDebtProof);

        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(existingBurn.burnId);
        vm.warp(readyAt);
        reserve.executeWithdrawal(existingBurn);
        assertTrue(reserve.paidBurns(existingBurn.burnId));
    }

    function testGracefulShutdownWaitsForEveryLiabilityWithoutBlockingPayout() public {
        (USDOMProofReserve.FinalizedBurn memory burn,) = queued(100e6);
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        checkpointRegistry.setTerminal(INITIAL, INITIAL, true, true);
        vm.expectRevert(USDOMProofReserve.NotGracefullyClosable.selector);
        reserve.finalizeGracefulShutdown();

        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(burn.burnId);
        vm.warp(readyAt);
        reserve.executeWithdrawal(burn);
        assertTrue(reserve.paidBurns(burn.burnId));
        assertFalse(reserve.gracefullyShutdown());
    }

    function testGracefulShutdownRequiresPinnedRegistryTerminalState() public {
        USDOMProofReserve empty = new USDOMProofReserve(config());
        guardian.execute(address(empty), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));

        checkpointRegistry.setTerminal(0, 0, false, true);
        vm.expectRevert(USDOMProofReserve.NotGracefullyClosable.selector);
        empty.finalizeGracefulShutdown();
        checkpointRegistry.setTerminal(1, 0, true, true);
        vm.expectRevert(USDOMProofReserve.NotGracefullyClosable.selector);
        empty.finalizeGracefulShutdown();
        checkpointRegistry.setTerminal(1, 1, true, true);
        vm.expectRevert(USDOMProofReserve.NotGracefullyClosable.selector);
        empty.finalizeGracefulShutdown();
        checkpointRegistry.setTerminal(0, 0, true, true);
        empty.finalizeGracefulShutdown();
        assertTrue(empty.gracefullyShutdown());

        vm.expectRevert(USDOMProofReserve.NotGracefullyClosable.selector);
        empty.finalizeGracefulShutdown();
    }

    function testGracefulShutdownFailsClosedIfPinnedRegistryIdentityChanges() public {
        USDOMProofReserve empty = new USDOMProofReserve(config());
        guardian.execute(address(empty), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        checkpointRegistry.setTerminal(0, 0, true, true);
        checkpointRegistry.setCheckpointConfigHash(keccak256("changed registry"));
        vm.expectRevert(USDOMProofReserve.RegistryChanged.selector);
        empty.finalizeGracefulShutdown();
    }

    function testEmergencyPauseInvalidatesLeaseButOnlyExactDebtCanRenew() public {
        (USDOMProofReserve.FinalizedBurn memory oldBurn, bytes memory oldProof) = queued(100e6);
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
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(replacement, replacementProof);
        reserve.queueWithdrawal(oldBurn, oldProof);
        assertEq(reserve.pendingRequests(oldBurn.requestId), oldBurn.burnId);
        assertEq(reserve.totalPendingAmount(), oldBurn.amount);
        assertEq(reserve.pendingCount(), 1);

        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(oldBurn);
        assertTrue(reserve.paidBurns(oldBurn.burnId));
        assertTrue(reserve.paidRequests(oldBurn.requestId));
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
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(replacement, replacementProof);
        bytes memory oldProof = proofFor(oldBurn);
        reserve.queueWithdrawal(oldBurn, oldProof);

        bytes memory stalePause = abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (observedEpoch));
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        guardian.execute(address(reserve), stalePause);
        assertFalse(reserve.paused());
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), oldBurn.amount);

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

        expired.finalityBeaconSlot = _currentBeaconSlot();
        bytes memory proof = proofFor(expired);
        approve(expired, proof);
        reserve.queueWithdrawal(expired, proof);
        vm.warp(block.timestamp + 1 days);
        reserve.executeWithdrawal(expired);
        expired.finalityBeaconSlot = _currentBeaconSlot();
        proof = proofFor(expired);
        approve(expired, proof);
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(expired, proof);
    }

    function testExpiredDebtKeepsPermanentBurnRequestAndStatementBindings() public {
        (USDOMProofReserve.FinalizedBurn memory original,) = queued(100e6);
        bytes32 statementHash = reserve.burnStatementHash(original);
        bytes32 debtHash = reserve.burnDebtHash(original);
        assertEq(reserve.provedBurnStatements(original.burnId), statementHash);
        assertEq(reserve.provedBurnDebts(original.burnId), debtHash);
        assertEq(reserve.provedRequestBurns(original.requestId), original.burnId);
        (,,, uint64 queueExpiry,,,,) = reserve.pendingWithdrawals(original.burnId);
        vm.warp(queueExpiry + 1);
        reserve.discardWithdrawal(original.burnId);

        USDOMProofReserve.FinalizedBurn memory changed = original;
        changed.finalityBeaconSlot += 1;
        bytes memory changedProof = proofFor(changed);
        approve(changed, changedProof);
        reserve.queueWithdrawal(changed, changedProof);
        assertEq(reserve.provedBurnDebts(original.burnId), debtHash);
        assertEq(reserve.provedBurnStatements(original.burnId), statementHash);
        (,,, uint64 renewedExpiry,,,,) = reserve.pendingWithdrawals(original.burnId);
        vm.warp(renewedExpiry + 1);
        reserve.discardWithdrawal(original.burnId);

        USDOMProofReserve.FinalizedBurn memory replacement = burn(original.amount);
        replacement.requestId = original.requestId;
        bytes memory replacementProof = proofFor(replacement);
        approve(replacement, replacementProof);
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(replacement, replacementProof);

        original.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        bytes memory unprovedRenewal = canonicalRiscZeroProof(keccak256("unproved renewal"));
        vm.expectRevert(USDOMProofReserve.InvalidProof.selector);
        reserve.queueWithdrawal(original, unprovedRenewal);
        bytes memory renewalProof = proofFor(original);
        approve(original, renewalProof);
        reserve.queueWithdrawal(original, renewalProof);
        assertEq(reserve.provedBurnFinalitySlots(original.burnId), original.finalityBeaconSlot);
        assertEq(reserve.pendingRequests(original.requestId), original.burnId);
        assertEq(reserve.provedBurnStatements(original.burnId), statementHash);
        assertEq(reserve.provedBurnDebts(original.burnId), debtHash);
        assertEq(reserve.provedRequestBurns(original.requestId), original.burnId);
    }

    function testLegitimateDebtSurvivesBlacklistExpiryPauseAndVerifierDrift() public {
        (USDOMProofReserve.FinalizedBurn memory b, bytes memory proof) = queued(100e6);
        bytes32 originallyProvedStatement = reserve.burnStatementHash(b);
        (,,, uint64 firstExpiry,,,,) = reserve.pendingWithdrawals(b.burnId);

        token.setBlocked(BOB);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(USDOMProofReserve.FrozenTokenAccount.selector, BOB));
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalPendingAmount(), b.amount);

        vm.warp(uint256(firstExpiry) + 1);
        reserve.discardWithdrawal(b.burnId);
        token.setBlocked(address(0));
        b.finalityBeaconSlot = _currentBeaconSlot();
        proof = proofFor(b);
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertTrue(reserve.paused());
        reserve.discardWithdrawal(b.burnId);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(block.timestamp + reserve.governanceDelay());
        reserve.executeResume();

        b.finalityBeaconSlot = _currentBeaconSlot();
        proof = proofFor(b);
        approve(b, proof);
        reserve.queueWithdrawal(b, proof);
        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(b.burnId);
        vm.warp(readyAt);
        bytes32 originalConfig = burnVerifier.verifierConfigHash();
        burnVerifier.setConfigHash(keccak256("temporary liveness drift"));
        vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
        reserve.executeWithdrawal(b);
        assertFalse(reserve.paidBurns(b.burnId));
        assertEq(reserve.provedBurnStatements(b.burnId), originallyProvedStatement);

        burnVerifier.setConfigHash(originalConfig);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
        assertEq(reserve.totalPendingAmount(), 0);
    }

    function testReservationsAndRateLimitCannotExceedCreditedCollateral() public {
        uint256 start = block.timestamp;
        (USDOMProofReserve.FinalizedBurn memory first,) = queued(FLOW);
        USDOMProofReserve.FinalizedBurn memory second = burn(FLOW);
        bytes memory secondProof = proofFor(second);
        approve(second, secondProof);
        reserve.queueWithdrawal(second, secondProof);
        assertEq(reserve.totalPendingAmount(), FLOW * 2);
        vm.warp(start + 1 days);
        reserve.executeWithdrawal(first);
        vm.expectRevert(USDOMProofReserve.OutflowLimit.selector);
        reserve.executeWithdrawal(second);
        vm.warp(start + 2 days);
        reserve.executeWithdrawal(second);
        assertEq(reserve.totalReleased(), FLOW * 2);
    }

    function testFractionalRefillAndExecutionOrderCannotOverspendBucket() public {
        (USDOMProofReserve.FinalizedBurn memory full,) = queued(FLOW);
        (USDOMProofReserve.FinalizedBurn memory firstHalf,) = queued(FLOW / 2);
        (USDOMProofReserve.FinalizedBurn memory secondHalf,) = queued(FLOW / 2);

        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(full);
        assertEq(reserve.availableOutflow(), 0);

        vm.warp(block.timestamp + reserve.REFILL_PERIOD() / 2);
        assertEq(reserve.availableOutflow(), FLOW / 2);
        // Any executable debt may consume the shared bucket. Changing order
        // cannot create more capacity or consume a failed attempt.
        reserve.executeWithdrawal(secondHalf);
        assertEq(reserve.availableOutflow(), 0);
        vm.expectRevert(USDOMProofReserve.OutflowLimit.selector);
        reserve.executeWithdrawal(firstHalf);
        assertEq(reserve.availableOutflow(), 0);

        vm.warp(block.timestamp + reserve.REFILL_PERIOD() / 2);
        reserve.executeWithdrawal(firstHalf);
        assertEq(reserve.totalReleased(), uint256(FLOW) * 2);
        assertEq(reserve.availableOutflow(), 0);
    }

    function testPauseDoesNotResetBucketAndElapsedTimeRefillsAtNormalRate() public {
        (USDOMProofReserve.FinalizedBurn memory full,) = queued(FLOW);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(full);
        assertEq(reserve.availableOutflow(), 0);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertEq(reserve.availableOutflow(), 0);
        vm.warp(block.timestamp + reserve.REFILL_PERIOD() / 2);
        assertEq(reserve.availableOutflow(), FLOW / 2);

        // Pause only blocks execution and invalidates queue leases. It neither
        // grants an artificial refill nor freezes the protocol clock.
        USDOMProofReserve.FinalizedBurn memory blocked = burn(1);
        vm.expectRevert(USDOMProofReserve.IsPaused.selector);
        reserve.executeWithdrawal(blocked);
        assertEq(reserve.availableOutflow(), FLOW / 2);
    }

    function testUnsafeTokenPolicyFailsClosedWithoutConsumingProof() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        approve(b, proof);
        token.setPolicy(true, false, 0, 0, false);
        USDOMProofReserve.FinalizedBurn memory oversized = burn(reserve.outflowCapacity() + 1);
        vm.expectRevert(USDOMProofReserve.OutflowLimit.selector);
        reserve.queueWithdrawal(oversized, proofFor(oversized));
        vm.expectRevert(USDOMProofReserve.UnsafeTokenState.selector);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), 0);
        token.setPolicy(false, false, 0, 0, false);
        reserve.queueWithdrawal(b, proof);
        assertEq(reserve.totalPendingAmount(), b.amount);
        token.setPolicy(true, false, 0, 0, false);
        vm.expectRevert(USDOMProofReserve.AlreadyUsed.selector);
        reserve.queueWithdrawal(b, proof);
    }

    function testTimestampNarrowingAndProofSizeFailClosed() public {
        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory oversized = new bytes(reserve.MAX_PROOF_BYTES() + 1);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, oversized);
        bytes memory truncated = new bytes(reserve.EVM_PROOF_BYTES() - 1);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, truncated);
        bytes memory wrongSelector = canonicalRiscZeroProof(bytes32(uint256(1)));
        wrongSelector[0] ^= 0x01;
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(b, wrongSelector);
        assertEq(reserve.totalPendingAmount(), 0);

        vm.warp(type(uint64).max);
        b.finalityBeaconSlot =
            uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
        vm.expectRevert(USDOMProofReserve.TimestampOverflow.selector);
        reserve.queueWithdrawal(b, canonicalRiscZeroProof(bytes32(uint256(1))));
    }

    function testResumeSchedulingTimestampOverflowFailsClosed() public {
        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.warp(type(uint64).max);
        vm.expectRevert(USDOMProofReserve.TimestampOverflow.selector);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        assertEq(reserve.resumeReadyAt(), 0);
        assertTrue(reserve.paused());
    }

    function _assertReleasedLog(Vm.Log[] memory logs, USDOMProofReserve.FinalizedBurn memory b) private view {
        bytes32 signature = keccak256("Released(bytes32,bytes32,address,uint64,uint64,bytes32,bytes32,uint64)");
        uint256 matches;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(reserve) || logs[i].topics[0] != signature) continue;
            ++matches;
            assertEq(logs[i].topics.length, 4);
            assertEq(logs[i].topics[1], b.burnId);
            assertEq(logs[i].topics[2], b.requestId);
            assertEq(logs[i].topics[3], bytes32(uint256(uint160(b.recipient))));
            (uint64 amount, uint64 height, bytes32 blockHash, bytes32 stateRoot, uint64 finalityBeaconSlot) =
                abi.decode(logs[i].data, (uint64, uint64, bytes32, bytes32, uint64));
            assertEq(amount, b.amount);
            assertEq(height, b.height);
            assertEq(blockHash, b.blockHash);
            assertEq(stateRoot, b.stateRoot);
            assertEq(finalityBeaconSlot, b.finalityBeaconSlot);
        }
        assertEq(matches, 1);
    }

    function _assertQueuePages(uint64 epoch, bytes32 firstId, bytes32 middleId, bytes32 lastId) private {
        (bytes32[] memory firstPage, bytes32 nextCursor) = reserve.pendingBurnPage(epoch, bytes32(0), 2);
        assertEq(firstPage.length, 2);
        assertEq(firstPage[0], firstId);
        assertEq(firstPage[1], middleId);
        assertEq(nextCursor, lastId);
        (bytes32[] memory lastPage, bytes32 endCursor) = reserve.pendingBurnPage(epoch, nextCursor, 2);
        assertEq(lastPage.length, 1);
        assertEq(lastPage[0], lastId);
        assertEq(endCursor, bytes32(0));

        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), 0);
        uint256 maximum = reserve.MAX_PRUNE_BATCH();
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        reserve.pendingBurnPage(epoch, bytes32(0), maximum + 1);
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.pendingBurnPage(epoch, keccak256("unknown queue cursor"), 1);
    }

    function _pendingFieldSlot(bytes32 burnId, uint256 fieldOffset) private pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode(burnId, uint256(5)))) + fieldOffset);
    }

    function _uniqueScalarSlot(bytes32 value) private view returns (bytes32 result) {
        // Solidity assigns this contract's declared scalar state near the
        // beginning of storage. Keep discovery deliberately bounded and demand
        // exactly one match so layout drift cannot make this corruption test
        // mutate an arbitrary or ambiguous slot and still pass.
        uint256 matches;
        for (uint256 i; i < 64; ++i) {
            if (vm.load(address(reserve), bytes32(i)) == value) {
                result = bytes32(i);
                ++matches;
            }
        }
        assertEq(matches, 1);
    }

    function _withQueueEpoch(bytes32 packed, uint64 epoch) private pure returns (bytes32) {
        uint256 epochMask = uint256(type(uint64).max) << 128;
        return bytes32((uint256(packed) & ~epochMask) | (uint256(epoch) << 128));
    }

    function _currentBeaconSlot() private view returns (uint64) {
        return uint64((block.timestamp - reserve.ETHEREUM_MAINNET_GENESIS_TIME()) / reserve.ETHEREUM_SECONDS_PER_SLOT());
    }

    function _assertNoReserveLogs(Vm.Log[] memory logs) private view {
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].emitter != address(reserve));
        }
    }
}
