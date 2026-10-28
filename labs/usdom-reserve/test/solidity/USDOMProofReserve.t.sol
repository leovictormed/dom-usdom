// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IDOMFinalizedBurnVerifier} from "../../contracts/IDOMFinalizedBurnVerifier.sol";
import {IDOMGracefulShutdownRegistry, USDOMProofReserve} from "../../contracts/USDOMProofReserve.sol";
import {TestBase, Vm} from "./TestBase.sol";
import {HostileToken, MockGovernance, MockGracefulShutdownRegistry, MockMutableSingletonControl} from "./Mocks.sol";

contract MockFinalizedBurnVerifier is IDOMFinalizedBurnVerifier {
    bytes32 private capability = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 private configHash = keccak256("DOM verifier test configuration");
    uint8 private configReturnMode;
    uint8 private capabilityReturnMode;
    mapping(bytes32 => bool) private accepted;

    function approve(bytes32 statementHash, bytes calldata proof) external {
        accepted[keccak256(abi.encode(statementHash, proof))] = true;
    }

    function setConfigHash(bytes32 value) external {
        configHash = value;
    }

    function setCapability(bytes32 value) external {
        capability = value;
    }

    function setConfigReturnMode(uint8 value) external {
        configReturnMode = value;
    }

    function setCapabilityReturnMode(uint8 value) external {
        capabilityReturnMode = value;
    }

    function verifierConfigHash() external view override returns (bytes32) {
        return _word(configHash, configReturnMode);
    }

    function PROOF_ACCEPTED() external view returns (bytes32) {
        return _word(capability, capabilityReturnMode);
    }

    function _word(bytes32 value, uint8 mode) private pure returns (bytes32) {
        if (mode != 0) {
            uint256 size = mode == 1 ? 31 : mode == 2 ? 33 : 0x100000;
            assembly ("memory-safe") {
                mstore(0, value)
                return(0, size)
            }
        }
        return value;
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
    bytes32 internal constant ETHEREUM_USDT_CODE_HASH =
        0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55;
    address internal constant SAFE_MAINNET_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    bytes32 internal constant SAFE_MAINNET_SINGLETON_CODE_HASH =
        0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4;
    bytes32 internal constant SAFE_MAINNET_PROXY_CODE_HASH =
        0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c;
    bytes32 internal constant PROOF_ACCEPTED = keccak256("USDOM_FINALIZED_BURN_PROOF_V1");
    bytes32 internal constant RESERVE_IDENTITY_TYPEHASH = keccak256(
        "ReserveIdentity(uint256 ethereumChainId,address reserve,address token,bytes32 tokenCodeHash,address verifier,bytes32 verifierCodeHash,bytes32 verifierConfigHash,address checkpointRegistry,bytes32 checkpointRegistryCodeHash,bytes32 checkpointConfigHash,bytes32 domDomain,bytes32 activationScheduleCommitment)"
    );
    bytes32 internal constant CONTROL_PLANE_IDENTITY_TYPEHASH = keccak256(
        "ControlPlaneIdentity(address account,bytes32 accountCodeHash,address implementation,bytes32 implementationCodeHash,bytes32 ownersCommitment)"
    );
    bytes32 internal constant RESERVE_POLICY_TYPEHASH = keccak256(
        "ReservePolicy(bytes32 governanceIdentityHash,bytes32 guardianIdentityHash,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity,bool pilotRestricted)"
    );
    bytes32 internal constant RESERVE_CONFIG_TYPEHASH =
        keccak256("ReserveConfig(bytes32 identityHash,bytes32 policyHash)");
    bytes32 internal constant BURN_STATEMENT_TYPEHASH = keccak256(
        "FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)"
    );

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
            FLOW,
            false
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
        assertFalse(reserve.paused());
    }

    function testReserveConfigurationHashBindsTheExactDeployment() public view {
        bytes32 identityHash = keccak256(
            bytes.concat(
                abi.encode(
                    RESERVE_IDENTITY_TYPEHASH,
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
                RESERVE_POLICY_TYPEHASH,
                keccak256(
                    abi.encode(
                        CONTROL_PLANE_IDENTITY_TYPEHASH,
                        address(governor),
                        address(governor).codehash,
                        address(governor),
                        address(governor).codehash,
                        bytes32(0)
                    )
                ),
                keccak256(
                    abi.encode(
                        CONTROL_PLANE_IDENTITY_TYPEHASH,
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
                FLOW,
                false
            )
        );
        bytes32 expected = keccak256(abi.encode(RESERVE_CONFIG_TYPEHASH, identityHash, policyHash));
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
        uint256 scalarField = BN254_SCALAR_FIELD;
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

    function testRestrictedPilotRejectsFrontRunTupleDriftReplayAndDelaysPermissionlessOpening() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("restricted pilot salt");
        bytes32 commitment = canonicalCommitment(keccak256("restricted pilot commitment"));
        bytes32 snapshot = keccak256("reviewed pilot snapshot");
        uint64 pilotValidUntil = uint64(block.timestamp + 1 days);

        vm.prank(BOB);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        pilot.deposit(1, salt, commitment);

        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (snapshot, ALICE, uint64(1), salt, commitment, pilotValidUntil, pilot.pilotAuthorizationGeneration())
            )
        );
        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.IsPaused.selector);
        pilot.deposit(1, salt, commitment);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        uint64 resumedAt = pilot.resumeReadyAt();
        vm.warp(resumedAt);
        pilot.executeResume();
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (
                    snapshot,
                    ALICE,
                    uint64(1),
                    salt,
                    commitment,
                    uint64(resumedAt + 1 days),
                    pilot.pilotAuthorizationGeneration()
                )
            )
        );
        vm.startPrank(ALICE);
        token.approve(address(pilot), 1);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        pilot.deposit(1, bytes32(uint256(salt) + 1), commitment);
        pilot.deposit(1, salt, commitment);
        assertTrue(pilot.pilotDepositConsumed());
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        pilot.deposit(1, salt, commitment);
        vm.stopPrank();

        vm.expectRevert(USDOMProofReserve.PilotNotSettled.selector);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.schedulePermissionlessDeposits, ()));

        USDOMProofReserve.FinalizedBurn memory b = burn(1);
        bytes memory proof = proofFor(b);
        burnVerifier.approve(pilot.burnStatementHash(b), proof);
        pilot.queueWithdrawal(b, proof);
        vm.warp(uint256(resumedAt) + 1 days);
        pilot.executeWithdrawal(b);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.schedulePermissionlessDeposits, ()));
        uint64 readyAt = pilot.permissionlessDepositsReadyAt();
        vm.expectRevert(USDOMProofReserve.TooEarly.selector);
        pilot.executePermissionlessDeposits();
        vm.warp(readyAt);
        pilot.executePermissionlessDeposits();
        assertTrue(pilot.permissionlessDeposits());

        token.mint(BOB, 1);
        vm.startPrank(BOB);
        token.approve(address(pilot), 1);
        pilot.deposit(1, keccak256("permissionless salt"), commitment);
        vm.stopPrank();
    }

    function testRestrictedPilotRequiresExactSingleUseAllowanceAndRollsBackOnResidualCapability() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("exact pilot allowance salt");
        bytes32 commitment = canonicalCommitment(keccak256("exact pilot allowance commitment"));
        bytes32 snapshot = keccak256("exact pilot allowance snapshot");
        uint64 validUntil = uint64(block.timestamp + 1 days);
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (snapshot, ALICE, uint64(1), salt, commitment, validUntil, pilot.pilotAuthorizationGeneration())
            )
        );

        token.mint(ALICE, 1);
        vm.startPrank(ALICE);
        token.approve(address(pilot), 2);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        pilot.deposit(1, salt, commitment);
        assertEq(token.allowance(ALICE, address(pilot)), 2);
        assertFalse(pilot.pilotDepositConsumed());
        assertEq(pilot.totalDeposited(), 0);

        token.approve(address(pilot), 1);
        token.setMode(HostileToken.Mode.ResidualAllowance);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        pilot.deposit(1, salt, commitment);
        assertEq(token.allowance(ALICE, address(pilot)), 1);
        assertFalse(pilot.pilotDepositConsumed());
        assertEq(pilot.totalDeposited(), 0);

        token.setMode(HostileToken.Mode.Standard);
        pilot.deposit(1, salt, commitment);
        assertEq(token.allowance(ALICE, address(pilot)), 0);
        assertTrue(pilot.pilotDepositConsumed());
        assertEq(pilot.totalDeposited(), 1);
        vm.stopPrank();
    }

    function testRestrictedPilotAllowanceProbeIsBoundedCanonicalAndRetryable() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("hostile pilot allowance returndata salt");
        bytes32 commitment = canonicalCommitment(keccak256("hostile pilot allowance returndata commitment"));
        bytes32 snapshot = keccak256("hostile pilot allowance returndata snapshot");
        uint64 validUntil = uint64(block.timestamp + 1 days);
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (snapshot, ALICE, uint64(1), salt, commitment, validUntil, pilot.pilotAuthorizationGeneration())
            )
        );
        token.mint(ALICE, 1);
        vm.startPrank(ALICE);
        token.approve(address(pilot), 1);
        bytes4 allowanceSelector = bytes4(keccak256("allowance(address,address)"));
        for (uint8 mode = 1; mode <= 5; ++mode) {
            token.setPolicyReturnMode(allowanceSelector, mode);
            vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
            pilot.deposit(1, salt, commitment);
            assertFalse(pilot.pilotDepositConsumed());
            assertEq(pilot.totalDeposited(), 0);
        }
        token.setPolicyReturnMode(bytes4(0), 0);
        pilot.deposit(1, salt, commitment);
        assertEq(token.allowance(ALICE, address(pilot)), 0);
        assertTrue(pilot.pilotDepositConsumed());
        vm.stopPrank();
    }

    function testRestrictedPilotAuthorizationAndConsumptionRollbackAreExact() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("rollback pilot salt");
        bytes32 commitment = canonicalCommitment(keccak256("rollback pilot commitment"));
        bytes32 snapshot = keccak256("exact reviewed pilot snapshot");
        uint64 pilotValidUntil = uint64(block.timestamp + 1 days);
        bytes32 authorization = pilot.pilotDepositAuthorization(ALICE, 1, salt, commitment, pilotValidUntil, 0);

        vm.recordLogs();
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (snapshot, ALICE, uint64(1), salt, commitment, pilotValidUntil, pilot.pilotAuthorizationGeneration())
            )
        );
        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool exactEvent;
        bytes32 topic = keccak256("PilotDepositAuthorized(bytes32,bytes32,uint64,uint64)");
        for (uint256 i; i < entries.length; ++i) {
            if (
                entries[i].emitter == address(pilot) && entries[i].topics.length == 3 && entries[i].topics[0] == topic
                    && entries[i].topics[1] == snapshot && entries[i].topics[2] == authorization
                    && keccak256(entries[i].data) == keccak256(abi.encode(pilotValidUntil, uint64(0)))
            ) exactEvent = true;
        }
        assertTrue(exactEvent);
        assertEq(pilot.authorizedPilotSnapshot(), snapshot);
        assertEq(pilot.authorizedPilotDeposit(), authorization);
        assertEq(pilot.pilotAuthorizationGeneration(), 0);

        token.mint(ALICE, 1);
        vm.startPrank(ALICE);
        token.approve(address(pilot), 1);
        token.setMode(HostileToken.Mode.Lie);
        vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
        pilot.deposit(1, salt, commitment);
        vm.stopPrank();
        assertFalse(pilot.pilotDepositConsumed());
        assertEq(pilot.authorizedPilotSnapshot(), snapshot);
        assertEq(pilot.authorizedPilotDeposit(), authorization);
        assertEq(pilot.pilotAuthorizationGeneration(), 0);
        assertEq(pilot.totalDeposited(), 0);

        token.setMode(HostileToken.Mode.Standard);
        vm.prank(ALICE);
        pilot.deposit(1, salt, commitment);
        assertTrue(pilot.pilotDepositConsumed());
        assertEq(pilot.authorizedPilotSnapshot(), bytes32(0));
        assertEq(pilot.authorizedPilotDeposit(), bytes32(0));
        assertEq(pilot.pilotAuthorizationGeneration(), 1);
    }

    function testPilotAuthorizationHashMatchesCanonicalAbiAndBindsEveryField() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("pilot hash salt");
        bytes32 commitment = canonicalCommitment(keccak256("pilot hash commitment"));
        uint64 validUntil = uint64(block.timestamp + 1 days);
        uint64 generation = 7;
        bytes32 expected = keccak256(
            abi.encode(block.chainid, address(pilot), ALICE, uint64(1e6), salt, commitment, validUntil, generation)
        );
        bytes32 actual = pilot.pilotDepositAuthorization(ALICE, 1e6, salt, commitment, validUntil, generation);
        assertEq(actual, expected);
        assertTrue(actual != pilot.pilotDepositAuthorization(BOB, 1e6, salt, commitment, validUntil, generation));
        assertTrue(actual != pilot.pilotDepositAuthorization(ALICE, 1e6 + 1, salt, commitment, validUntil, generation));
        assertTrue(
            actual
                != pilot.pilotDepositAuthorization(
                    ALICE, 1e6, bytes32(uint256(salt) + 1), commitment, validUntil, generation
                )
        );
        assertTrue(
            actual
                != pilot.pilotDepositAuthorization(
                    ALICE, 1e6, salt, bytes32(uint256(commitment) + 1), validUntil, generation
                )
        );
        assertTrue(actual != pilot.pilotDepositAuthorization(ALICE, 1e6, salt, commitment, validUntil + 1, generation));
        assertTrue(actual != pilot.pilotDepositAuthorization(ALICE, 1e6, salt, commitment, validUntil, generation + 1));

        USDOMProofReserve other = new USDOMProofReserve(c);
        assertTrue(actual != other.pilotDepositAuthorization(ALICE, 1e6, salt, commitment, validUntil, generation));
    }

    function testLegacyConstructorTupleWithoutPilotRestrictedIsRejected() public {
        USDOMProofReserve.Config memory c = config();
        bytes memory legacyInitcode = abi.encodePacked(
            type(USDOMProofReserve).creationCode,
            abi.encode(
                c.token,
                c.verifier,
                c.checkpointRegistry,
                c.domDomain,
                c.activationScheduleCommitment,
                c.governance,
                c.guardian,
                c.withdrawalDelay,
                c.governanceDelay,
                c.maxOutstanding,
                c.outflowCapacity
            )
        );
        address deployed;
        assembly ("memory-safe") {
            deployed := create(0, add(legacyInitcode, 0x20), mload(legacyInitcode))
        }
        assertEq(deployed, address(0));
    }

    function testPendingQueueSnapshotIsAtomicallyEquivalentToQueueState() public {
        (uint64 epoch, uint256 count, uint256 amount, bytes32 first, bytes32 last) = reserve.pendingQueueSnapshot();
        assertEq(epoch, reserve.queueEpoch());
        assertEq(count, 0);
        assertEq(amount, 0);
        assertEq(first, bytes32(0));
        assertEq(last, bytes32(0));

        USDOMProofReserve.FinalizedBurn memory firstBurn = burn(1e6);
        bytes memory firstProof = proofFor(firstBurn);
        burnVerifier.approve(reserve.burnStatementHash(firstBurn), firstProof);
        reserve.queueWithdrawal(firstBurn, firstProof);
        USDOMProofReserve.FinalizedBurn memory secondBurn = burn(2e6);
        bytes memory secondProof = proofFor(secondBurn);
        burnVerifier.approve(reserve.burnStatementHash(secondBurn), secondProof);
        reserve.queueWithdrawal(secondBurn, secondProof);

        (epoch, count, amount, first, last) = reserve.pendingQueueSnapshot();
        assertEq(epoch, reserve.queueEpoch());
        assertEq(count, reserve.pendingCount());
        assertEq(amount, reserve.totalPendingAmount());
        assertEq(first, reserve.firstPendingBurn());
        assertEq(last, reserve.lastPendingBurn());
        assertEq(count, 2);
        assertEq(amount, 3e6);
        assertEq(first, firstBurn.burnId);
        assertEq(last, secondBurn.burnId);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        (uint64 resetEpoch, uint256 resetCount, uint256 resetAmount, bytes32 resetFirst, bytes32 resetLast) =
            reserve.pendingQueueSnapshot();
        assertEq(resetEpoch, epoch + 1);
        assertEq(resetCount, 0);
        assertEq(resetAmount, 0);
        assertEq(resetFirst, bytes32(0));
        assertEq(resetLast, bytes32(0));
    }

    function testRestrictedPilotOpeningScheduleIsCancelledByPauseAndPermanentClose() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("opening pilot salt");
        bytes32 commitment = canonicalCommitment(keccak256("opening pilot commitment"));
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (
                    keccak256("opening snapshot"),
                    ALICE,
                    uint64(1),
                    salt,
                    commitment,
                    uint64(block.timestamp + 1 days),
                    pilot.pilotAuthorizationGeneration()
                )
            )
        );
        vm.startPrank(ALICE);
        token.approve(address(pilot), 1);
        pilot.deposit(1, salt, commitment);
        vm.stopPrank();

        USDOMProofReserve.FinalizedBurn memory b = burn(1);
        bytes memory proof = proofFor(b);
        burnVerifier.approve(pilot.burnStatementHash(b), proof);
        pilot.queueWithdrawal(b, proof);
        vm.warp(block.timestamp + 1 days);
        pilot.executeWithdrawal(b);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.schedulePermissionlessDeposits, ()));
        uint64 staleReadyAt = pilot.permissionlessDepositsReadyAt();

        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.pause, ()));
        assertEq(pilot.permissionlessDepositsReadyAt(), 0);
        vm.warp(staleReadyAt);
        vm.expectRevert(USDOMProofReserve.IsPaused.selector);
        pilot.executePermissionlessDeposits();
        vm.expectRevert(USDOMProofReserve.IsPaused.selector);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.schedulePermissionlessDeposits, ()));

        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        uint64 resumeAt = pilot.resumeReadyAt();
        vm.warp(resumeAt);
        pilot.executeResume();
        vm.expectRevert(USDOMProofReserve.NoProposal.selector);
        pilot.executePermissionlessDeposits();
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.schedulePermissionlessDeposits, ()));
        assertTrue(pilot.permissionlessDepositsReadyAt() != 0);
        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        assertEq(pilot.permissionlessDepositsReadyAt(), 0);
        vm.expectRevert(USDOMProofReserve.NoProposal.selector);
        pilot.executePermissionlessDeposits();
        vm.expectRevert(USDOMProofReserve.DepositsClosed.selector);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.schedulePermissionlessDeposits, ()));
    }

    function testRestrictedPilotExpiryCancellationReauthorizationAndOldTupleReplay() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 oldSalt = keccak256("old pilot salt");
        bytes32 oldCommitment = canonicalCommitment(keccak256("old pilot commitment"));
        bytes32 oldSnapshot = keccak256("old pilot snapshot");
        uint64 oldValidUntil = uint64(block.timestamp + 10);
        bytes memory staleCancelledAuthorization = abi.encodeCall(
            USDOMProofReserve.authorizePilotDeposit,
            (oldSnapshot, ALICE, uint64(1), oldSalt, oldCommitment, oldValidUntil, uint64(0))
        );
        bytes memory staleCancellation =
            abi.encodeCall(USDOMProofReserve.cancelPilotDepositAuthorization, (oldSnapshot, uint64(0)));
        governor.execute(address(pilot), staleCancelledAuthorization);
        guardian.execute(address(pilot), staleCancellation);
        assertEq(pilot.pilotAuthorizationGeneration(), 1);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        governor.execute(address(pilot), staleCancelledAuthorization);
        bytes memory staleExpiredAuthorization = abi.encodeCall(
            USDOMProofReserve.authorizePilotDeposit,
            (oldSnapshot, ALICE, uint64(1), oldSalt, oldCommitment, oldValidUntil, uint64(1))
        );
        governor.execute(address(pilot), staleExpiredAuthorization);
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        guardian.execute(address(pilot), staleCancellation);
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        guardian.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.cancelPilotDepositAuthorization, (keccak256("foreign snapshot"), uint64(1))
            )
        );
        token.mint(ALICE, 2);
        vm.prank(ALICE);
        token.approve(address(pilot), 2);
        vm.warp(oldValidUntil + 1);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        pilot.deposit(1, oldSalt, oldCommitment);

        bytes memory staleAutomatedPause =
            abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (pilot.queueEpoch(), uint64(1)));
        vm.prank(BOB);
        pilot.clearExpiredPilotDepositAuthorization(oldSnapshot, 1);
        assertEq(pilot.authorizedPilotDeposit(), bytes32(0));
        assertEq(pilot.pilotAuthorizationGeneration(), 2);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        governor.execute(address(pilot), staleExpiredAuthorization);
        uint64 rearmedValidUntil = uint64(uint256(oldValidUntil) + 1 days);
        bytes memory stalePausedAuthorization = abi.encodeCall(
            USDOMProofReserve.authorizePilotDeposit,
            (oldSnapshot, ALICE, uint64(1), oldSalt, oldCommitment, rearmedValidUntil, uint64(2))
        );
        governor.execute(address(pilot), stalePausedAuthorization);
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        pilot.clearExpiredPilotDepositAuthorization(oldSnapshot, 1);
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        guardian.execute(address(pilot), staleAutomatedPause);
        vm.recordLogs();
        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.pause, ()));
        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes32 cancelTopic = keccak256("PilotDepositAuthorizationCancelled(bytes32,bytes32,uint64,uint64,address)");
        bool cancellationFound;
        for (uint256 i; i < entries.length; ++i) {
            if (
                entries[i].emitter == address(pilot) && entries[i].topics.length == 4
                    && entries[i].topics[0] == cancelTopic && entries[i].topics[1] == oldSnapshot
                    && entries[i].topics[3] == bytes32(uint256(uint160(address(guardian))))
                    && keccak256(entries[i].data) == keccak256(abi.encode(rearmedValidUntil, uint64(2)))
            ) cancellationFound = true;
        }
        assertTrue(cancellationFound);
        assertEq(pilot.authorizedPilotDeposit(), bytes32(0));
        assertEq(pilot.authorizedPilotSnapshot(), bytes32(0));
        assertEq(pilot.authorizedPilotValidUntil(), 0);
        assertEq(pilot.pilotAuthorizationGeneration(), 3);

        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        uint64 resumedAt = pilot.resumeReadyAt();
        vm.warp(resumedAt);
        pilot.executeResume();
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        governor.execute(address(pilot), stalePausedAuthorization);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        pilot.deposit(1, oldSalt, oldCommitment);

        bytes32 newSalt = keccak256("new pilot salt");
        bytes32 newCommitment = canonicalCommitment(keccak256("new pilot commitment"));
        uint64 newValidUntil = uint64(uint256(resumedAt) + 1 days);
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (
                    keccak256("new pilot snapshot"),
                    ALICE,
                    uint64(1),
                    newSalt,
                    newCommitment,
                    newValidUntil,
                    pilot.pilotAuthorizationGeneration()
                )
            )
        );
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        pilot.deposit(1, oldSalt, oldCommitment);
        vm.prank(ALICE);
        token.approve(address(pilot), 1);
        vm.prank(ALICE);
        pilot.deposit(1, newSalt, newCommitment);
        assertTrue(pilot.pilotDepositConsumed());
    }

    function testRestrictedPilotValidityBoundaryIsInclusiveAndHorizonIsBounded() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 salt = keccak256("boundary pilot salt");
        bytes32 commitment = canonicalCommitment(keccak256("boundary pilot commitment"));
        uint256 maximumLifetime = pilot.MAX_PILOT_AUTHORIZATION_LIFETIME();
        uint64 generation = pilot.pilotAuthorizationGeneration();
        vm.expectRevert(USDOMProofReserve.PilotDepositRestricted.selector);
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (
                    keccak256("too distant snapshot"),
                    ALICE,
                    uint64(1),
                    salt,
                    commitment,
                    uint64(block.timestamp + maximumLifetime + 1),
                    generation
                )
            )
        );
        uint64 boundary = uint64(block.timestamp);
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (keccak256("boundary snapshot"), ALICE, uint64(1), salt, commitment, boundary, generation)
            )
        );
        token.mint(ALICE, 1);
        vm.startPrank(ALICE);
        token.approve(address(pilot), 1);
        pilot.deposit(1, salt, commitment);
        vm.stopPrank();
        assertTrue(pilot.pilotDepositConsumed());
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

    function testRegistryReturnDataMustBeExactBoundedAndCanonical() public {
        bytes4 configSelector = bytes4(keccak256("checkpointConfigHash()"));
        bytes4 haltedSelector = bytes4(keccak256("halted()"));
        bytes32 salt = keccak256("hostile registry returndata");
        for (uint8 mode = 1; mode <= 3; ++mode) {
            checkpointRegistry.setReturnMode(configSelector, mode);
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.RegistryChanged.selector);
            reserve.deposit(1, salt, bytes32(uint256(1)));
        }
        for (uint8 mode = 1; mode <= 4; ++mode) {
            checkpointRegistry.setReturnMode(haltedSelector, mode);
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.RegistryChanged.selector);
            reserve.deposit(1, salt, bytes32(uint256(1)));
        }
        checkpointRegistry.setReturnMode(bytes4(0), 0);

        USDOMProofReserve empty = new USDOMProofReserve(config());
        guardian.execute(address(empty), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        checkpointRegistry.setTerminal(0, 0, true, true);
        bytes4[4] memory terminalSelectors = [
            bytes4(keccak256("gracefullyShutdown()")),
            bytes4(keccak256("latestIssuanceClosed()")),
            bytes4(keccak256("latestTotalIssued()")),
            bytes4(keccak256("latestTotalBurned()"))
        ];
        for (uint256 i; i < terminalSelectors.length; ++i) {
            for (uint8 mode = 1; mode <= 4; ++mode) {
                checkpointRegistry.setReturnMode(terminalSelectors[i], mode);
                vm.expectRevert();
                empty.finalizeGracefulShutdown();
                assertFalse(empty.gracefullyShutdown());
            }
        }
        checkpointRegistry.setReturnMode(bytes4(0), 0);
        empty.finalizeGracefulShutdown();
        assertTrue(empty.gracefullyShutdown());
    }

    function testCheckpointHaltDoesNotBlockExistingProvedDebtPayout() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(1e6);
        checkpointRegistry.setHalted(true);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
    }

    function testChainIdDriftBlocksNewExposureRenewalAndPayoutWithoutConsumingDebt() public {
        bytes32 salt = keccak256("deployment-chain-bound deposit");
        bytes32 id = reserve.depositId(ALICE, salt);
        (USDOMProofReserve.FinalizedBurn memory established,) = queued(1e6);
        bytes32 statement = reserve.burnStatementHash(established);
        uint256 originalChainId = reserve.deploymentChainId();

        vm.chainId(originalChainId + 1);
        assertEq(reserve.depositId(ALICE, salt), id);
        assertEq(reserve.burnStatementHash(established), statement);
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ChainChanged.selector);
        reserve.deposit(1, salt, bytes32(uint256(1)));

        USDOMProofReserve.FinalizedBurn memory fresh = burn(1e6);
        bytes memory freshProof = proofFor(fresh);
        approve(fresh, freshProof);
        vm.expectRevert(USDOMProofReserve.ChainChanged.selector);
        reserve.queueWithdrawal(fresh, freshProof);

        vm.warp(block.timestamp + reserve.withdrawalDelay());
        vm.expectRevert(USDOMProofReserve.ChainChanged.selector);
        reserve.executeWithdrawal(established);
        assertFalse(reserve.paidBurns(established.burnId));
        assertEq(reserve.totalProvedDebtAmount(), established.amount);

        vm.warp(block.timestamp + reserve.MAX_CERTIFICATE_LIFETIME());
        reserve.discardWithdrawal(established.burnId);
        vm.expectRevert(USDOMProofReserve.ChainChanged.selector);
        reserve.queueWithdrawal(established, bytes(""));

        vm.chainId(originalChainId);
        reserve.queueWithdrawal(established, bytes(""));
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        reserve.executeWithdrawal(established);
        assertTrue(reserve.paidBurns(established.burnId));
        assertEq(token.balanceOf(BOB), established.amount);
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

    function testTokenPolicyReturnDataMustBeExactBoundedAndCanonical() public {
        bytes4[6] memory selectors = [
            bytes4(keccak256("paused()")),
            bytes4(keccak256("deprecated()")),
            bytes4(keccak256("upgradedAddress()")),
            bytes4(keccak256("basisPointsRate()")),
            bytes4(keccak256("maximumFee()")),
            bytes4(keccak256("isBlackListed(address)"))
        ];
        bytes32 salt = keccak256("hostile token policy returndata");
        for (uint256 i; i < selectors.length; ++i) {
            for (uint8 mode = 1; mode <= 5; ++mode) {
                token.setPolicyReturnMode(selectors[i], mode);
                vm.prank(ALICE);
                vm.expectRevert();
                reserve.deposit(1, salt, bytes32(uint256(1)));
                (address funder,,) = reserve.deposits(reserve.depositId(ALICE, salt));
                assertEq(funder, address(0));
            }
        }
        token.setPolicyReturnMode(bytes4(0), 0);

        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        uint256 pendingBefore = reserve.totalPendingAmount();
        uint256 availableBefore = reserve.availableOutflow();
        uint8[2] memory hostileModes = [uint8(3), uint8(5)];
        for (uint256 i; i < hostileModes.length; ++i) {
            token.setPolicyReturnMode(bytes4(keccak256("isBlackListed(address)")), hostileModes[i]);
            vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
            reserve.executeWithdrawal(b);
            assertFalse(reserve.paidBurns(b.burnId));
            assertEq(reserve.totalPendingAmount(), pendingBefore);
            assertEq(reserve.availableOutflow(), availableBefore);
        }
        token.setPolicyReturnMode(bytes4(0), 0);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
    }

    function testTokenDecimalsAndBalanceReturnDataMustBeExactAndBounded() public {
        bytes4 decimalsSelector = bytes4(keccak256("decimals()"));
        for (uint8 mode = 1; mode <= 5; ++mode) {
            token.setPolicyReturnMode(decimalsSelector, mode);
            vm.expectRevert(USDOMProofReserve.UnsupportedToken.selector);
            new USDOMProofReserve(config());
        }
        token.setPolicyReturnMode(bytes4(0), 0);

        bytes4 balanceSelector = bytes4(keccak256("balanceOf(address)"));
        bytes32 salt = keccak256("hostile balance returndata");
        for (uint8 mode = 1; mode <= 5; ++mode) {
            token.setPolicyReturnMode(balanceSelector, mode);
            vm.prank(ALICE);
            vm.expectRevert();
            reserve.deposit(1, salt, bytes32(uint256(1)));
            (address funder,,) = reserve.deposits(reserve.depositId(ALICE, salt));
            assertEq(funder, address(0));
        }
        token.setPolicyReturnMode(bytes4(0), 0);

        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + reserve.withdrawalDelay());
        uint256 pendingBefore = reserve.totalPendingAmount();
        for (uint8 mode = 1; mode <= 5; ++mode) {
            token.setPolicyReturnMode(balanceSelector, mode);
            vm.expectRevert();
            reserve.executeWithdrawal(b);
            assertFalse(reserve.paidBurns(b.burnId));
            assertEq(reserve.totalPendingAmount(), pendingBefore);
        }
        token.setPolicyReturnMode(bytes4(0), 0);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
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

    function testVerifierIdentityReturnDataMustRemainExactAndBounded() public {
        bytes32 salt = keccak256("hostile verifier identity returndata");
        for (uint8 mode = 1; mode <= 3; ++mode) {
            burnVerifier.setConfigReturnMode(mode);
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
            reserve.deposit(1, salt, bytes32(uint256(1)));
        }
        burnVerifier.setConfigReturnMode(0);
        for (uint8 mode = 1; mode <= 3; ++mode) {
            burnVerifier.setCapabilityReturnMode(mode);
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.VerifierChanged.selector);
            reserve.deposit(1, salt, bytes32(uint256(1)));
        }
        burnVerifier.setCapabilityReturnMode(0);
        vm.prank(ALICE);
        reserve.deposit(1, salt, bytes32(uint256(1)));
        assertEq(reserve.totalDeposited(), INITIAL + 1);
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
        assertEq(SAFE_MAINNET_SINGLETON, 0x41675C099F32341bf84BFc5382aF534df5C7461a);
        assertEq(SAFE_MAINNET_SINGLETON_CODE_HASH, 0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4);
        assertEq(SAFE_MAINNET_PROXY_CODE_HASH, 0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c);
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
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

    function testProofBindsEveryPublicFieldDeploymentChainAndReserve() public {
        assertEq(BURN_STATEMENT_TYPEHASH, 0xb4a224b119278936bec16ab7cf63f13d2cc130395834d17a30335b9158062ced);
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

        bytes32 deploymentChainStatement = reserve.burnStatementHash(b);
        approve(b, proof);
        vm.chainId(block.chainid + 1);
        assertEq(deploymentChainStatement, reserve.burnStatementHash(b));
        vm.expectRevert(USDOMProofReserve.ChainChanged.selector);
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
        approve(b, proof);

        USDOMProofReserve.Config memory otherConfig = config();
        otherConfig.activationScheduleCommitment = keccak256("other activation schedule");
        otherConfig.checkpointRegistry = IDOMGracefulShutdownRegistry(
            address(new MockGracefulShutdownRegistry(DOMAIN, otherConfig.activationScheduleCommitment))
        );
        USDOMProofReserve otherActivation = new USDOMProofReserve(otherConfig);
        assertTrue(otherActivation.reserveConfigHash() != reserve.reserveConfigHash());
        assertTrue(otherActivation.burnStatementHash(b) != authorizedStatement);
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
                    BURN_STATEMENT_TYPEHASH,
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
                    keccak256(
                        "FinalizedBurnDebt(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)"
                    ),
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

        burnVerifier.setCapability(PROOF_ACCEPTED);
        vm.prank(ALICE);
        reserve.deposit(1, bytes32(uint256(0x6461)), bytes32(uint256(0x6462)));
        assertEq(reserve.totalDeposited(), INITIAL + 1);
    }

    function testTokenCodeIdentityIsImmutable() public {
        assertEq(ETHEREUM_USDT_CODE_HASH, 0xb44fb4e949d0f78f87f79ee46428f23a2a5713ce6fc6e0beb3dda78c2ac1ea55);
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
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
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
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);

        bytes32 initcodeHashBefore = keccak256(abi.encodePacked(type(USDOMProofReserve).creationCode, abi.encode(c)));
        USDOMProofReserve first = new USDOMProofReserve(c);
        bytes32 firstOwners = first.governanceOwnersCommitment();
        bytes32 firstIdentity = keccak256(
            abi.encode(
                CONTROL_PLANE_IDENTITY_TYPEHASH,
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
                CONTROL_PLANE_IDENTITY_TYPEHASH,
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
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
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
        assertEq(
            protectedReserve.guardianOwnersCommitment(),
            keccak256(abi.encode(address(0x201), address(0x202), address(0x203)))
        );

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
        safeGuardian.setOwner(2, address(0x203));
        for (uint8 mode = 1; mode <= 7; ++mode) {
            safeGuardian.setOwnersReturnMode(mode);
            assertFalse(protectedReserve.controlPlaneHealthy());
            vm.prank(ALICE);
            vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
            protectedReserve.deposit(1, bytes32(uint256(0x1200 + mode)), bytes32(uint256(0x1300 + mode)));
        }
        safeGuardian.setOwnersReturnMode(0);
        assertTrue(protectedReserve.controlPlaneHealthy());
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
        uint256 deploymentChain = protectedReserve.deploymentChainId();
        vm.chainId(deploymentChain + 1);
        assertTrue(protectedReserve.controlPlaneHealthy());
        safeGuardian.setThreshold(1);
        assertFalse(protectedReserve.controlPlaneHealthy());
        safeGuardian.setThreshold(2);
        assertTrue(protectedReserve.controlPlaneHealthy());
        vm.chainId(deploymentChain);
    }

    function testSafeOwnerCodeAppearanceAfterAdmissionDoesNotFreezeReserve() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);

        // Admission still excludes contract/delegated-code owners.
        vm.etch(address(0x101), hex"00");
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
        vm.etch(address(0x101), bytes(""));

        USDOMProofReserve protectedReserve = new USDOMProofReserve(c);
        vm.prank(ALICE);
        token.approve(address(protectedReserve), type(uint256).max);

        // EIP-7702 code appearance does not change the admitted owner address
        // or the 2-of-3 Safe authority, so one owner cannot halt deposits.
        vm.etch(address(0x101), hex"00");
        assertTrue(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        protectedReserve.deposit(1, bytes32(uint256(0x7702)), bytes32(uint256(0x7703)));

        // Actual policy and owner-set changes remain fail-closed.
        safeGovernance.setThreshold(1);
        assertFalse(protectedReserve.controlPlaneHealthy());
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(0x7704)), bytes32(uint256(0x7705)));
        safeGovernance.setThreshold(2);
        safeGovernance.setOwner(0, address(0x104));
        assertFalse(protectedReserve.controlPlaneHealthy());
    }

    function testSafeAuxiliaryReturnDataMustBeExactAndBounded() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);
        USDOMProofReserve protectedReserve = new USDOMProofReserve(c);

        for (uint8 mode = 1; mode <= 3; ++mode) {
            safeGovernance.setThresholdReturnMode(mode);
            assertFalse(protectedReserve.controlPlaneHealthy());
        }
        safeGovernance.setThresholdReturnMode(0);
        for (uint8 mode = 1; mode <= 4; ++mode) {
            safeGovernance.setModulesReturnMode(mode);
            assertFalse(protectedReserve.controlPlaneHealthy());
        }
        safeGovernance.setModulesReturnMode(0);
        for (uint8 mode = 1; mode <= 4; ++mode) {
            safeGovernance.setStorageReturnMode(mode);
            assertFalse(protectedReserve.controlPlaneHealthy());
        }
        safeGovernance.setStorageReturnMode(0);
        assertTrue(protectedReserve.controlPlaneHealthy());
    }

    function testSafeDriftBetweenQueueExecuteAndResumePreservesRetryableState() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
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
        protectedReserve.executeWithdrawal(b);
        assertTrue(protectedReserve.paidBurns(b.burnId));
        assertEq(protectedReserve.totalPendingAmount(), 0);
        assertEq(protectedReserve.totalReleased(), b.amount);
        assertEq(protectedReserve.availableOutflow(), availableBefore - b.amount);

        safeGovernance.setOwner(0, address(0x101));
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

        safeGuardian.setOwner(2, address(0x203));
        protectedReserve.executeResume();
        assertFalse(protectedReserve.paused());
        assertEq(protectedReserve.resumeReadyAt(), 0);
    }

    function testExpiredProvedDebtCanRenewAndSettleAfterSafeOwnerDrift() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);
        USDOMProofReserve protectedReserve = new USDOMProofReserve(c);

        vm.startPrank(ALICE);
        token.approve(address(protectedReserve), INITIAL);
        protectedReserve.deposit(
            INITIAL, keccak256("safe renewal deposit"), canonicalCommitment(keccak256("safe renewal commitment"))
        );
        vm.stopPrank();

        USDOMProofReserve.FinalizedBurn memory b = burn(100e6);
        bytes memory proof = proofFor(b);
        burnVerifier.approve(protectedReserve.burnStatementHash(b), proof);
        protectedReserve.queueWithdrawal(b, proof);
        vm.warp(block.timestamp + protectedReserve.MAX_CERTIFICATE_LIFETIME() + 1);
        protectedReserve.discardWithdrawal(b.burnId);

        safeGovernance.setOwner(0, address(0x104));
        assertFalse(protectedReserve.controlPlaneHealthy());
        protectedReserve.queueWithdrawal(b, bytes(""));
        assertEq(protectedReserve.totalProvedDebtAmount(), b.amount);
        assertEq(protectedReserve.totalPendingAmount(), b.amount);

        vm.warp(block.timestamp + protectedReserve.withdrawalDelay());
        protectedReserve.executeWithdrawal(b);
        assertTrue(protectedReserve.paidBurns(b.burnId));
        assertEq(protectedReserve.totalProvedDebtAmount(), 0);
        assertEq(protectedReserve.totalPendingAmount(), 0);

        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.ControlPlaneChanged.selector);
        protectedReserve.deposit(1, bytes32(uint256(0xD1)), bytes32(uint256(0xD2)));
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

        safeGovernance.setOwner(1, address(0x11));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        safeGovernance.setOwner(1, address(0x102));
        safeGovernance.setGuard(address(0xBEEF));
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);

        safeGovernance.setGuard(address(0));
        uint64 creatorNonce = vm.getNonce(address(this));
        // Foundry reports the test contract's external-account nonce; the next
        // CREATE uses the following nonce after this contract's own creation.
        ++creatorNonce;
        assertTrue(creatorNonce != 0 && creatorNonce <= 0x7f);
        address predictedReserve = address(
            uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), bytes1(uint8(creatorNonce))))))
        );
        safeGovernance.setOwner(1, predictedReserve);
        vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
        new USDOMProofReserve(c);
    }

    function testConstructorRejectsAnyOwnerSharedAcrossGovernanceAndGuardianSafes() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);

        address[3] memory governanceSet = [address(0x101), address(0x102), address(0x103)];
        for (uint256 governanceIndex; governanceIndex < governanceSet.length; ++governanceIndex) {
            for (uint256 guardianIndex; guardianIndex < 3; ++guardianIndex) {
                safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
                safeGuardian.setOwner(guardianIndex, governanceSet[governanceIndex]);
                vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
                new USDOMProofReserve(c);
            }
        }

        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
        USDOMProofReserve separated = new USDOMProofReserve(c);
        assertTrue(separated.governanceOwnersCommitment() != separated.guardianOwnersCommitment());
    }

    function testConstructorRejectsEveryMalformedOrUnboundedSafeOwnersResponse() public {
        MockGovernance implementation = new MockGovernance();
        MockMutableSingletonControl safeGovernance = new MockMutableSingletonControl(address(implementation));
        MockMutableSingletonControl safeGuardian = new MockMutableSingletonControl(address(implementation));
        safeGuardian.setOwners(address(0x201), address(0x202), address(0x203));
        USDOMProofReserve.Config memory c = config();
        c.governance = address(safeGovernance);
        c.guardian = address(safeGuardian);

        // Revert, short/trailing returndata, return bomb, noncanonical offset,
        // wrong count and dirty address padding must all fail closed.
        for (uint8 mode = 1; mode <= 7; ++mode) {
            safeGovernance.setOwnersReturnMode(mode);
            vm.expectRevert(USDOMProofReserve.InvalidConfiguration.selector);
            new USDOMProofReserve(c);
        }
        safeGovernance.setOwnersReturnMode(0);
        new USDOMProofReserve(c);
    }

    function testPilotAuthorizationCannotBeCreatedWhilePausedOrAfterIngressClosure() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes memory authorization = abi.encodeCall(
            USDOMProofReserve.authorizePilotDeposit,
            (
                keccak256("paused pilot snapshot"),
                ALICE,
                uint64(1),
                keccak256("paused pilot salt"),
                canonicalCommitment(keccak256("paused pilot commitment")),
                uint64(block.timestamp + 1 days),
                uint64(0)
            )
        );

        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.pause, ()));
        vm.expectRevert(USDOMProofReserve.IsPaused.selector);
        governor.execute(address(pilot), authorization);
        governor.execute(address(pilot), abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(pilot.resumeReadyAt());
        pilot.executeResume();
        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        vm.expectRevert(USDOMProofReserve.DepositsClosed.selector);
        governor.execute(address(pilot), authorization);
    }

    function testCloseDepositsAtomicallyInvalidatesActivePilotAuthorization() public {
        USDOMProofReserve.Config memory c = config();
        c.pilotRestricted = true;
        USDOMProofReserve pilot = new USDOMProofReserve(c);
        bytes32 snapshot = keccak256("closure pilot snapshot");
        governor.execute(
            address(pilot),
            abi.encodeCall(
                USDOMProofReserve.authorizePilotDeposit,
                (
                    snapshot,
                    ALICE,
                    uint64(1),
                    keccak256("closure pilot salt"),
                    canonicalCommitment(keccak256("closure pilot commitment")),
                    uint64(block.timestamp + 1 days),
                    uint64(0)
                )
            )
        );
        assertTrue(pilot.authorizedPilotDeposit() != bytes32(0));

        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.closeDeposits, ()));
        assertTrue(pilot.depositsClosed());
        assertEq(pilot.authorizedPilotDeposit(), bytes32(0));
        assertEq(pilot.authorizedPilotSnapshot(), bytes32(0));
        assertEq(pilot.authorizedPilotValidUntil(), 0);
        assertEq(pilot.permissionlessDepositsReadyAt(), 0);
        assertEq(pilot.pilotAuthorizationGeneration(), 1);

        checkpointRegistry.setTerminal(0, 0, true, true);
        pilot.finalizeGracefulShutdown();
        assertTrue(pilot.gracefullyShutdown());
        vm.expectRevert(USDOMProofReserve.NotGracefullyClosable.selector);
        guardian.execute(address(pilot), abi.encodeCall(USDOMProofReserve.pause, ()));
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

    function testDepositShutdownBlocksIngressButAllowsFirstProofAndPayouts() public {
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
        reserve.queueWithdrawal(newDebt, newDebtProof);
        assertEq(reserve.provedBurnDebts(newDebt.burnId), reserve.burnDebtHash(newDebt));
        assertEq(reserve.totalProvedDebtAmount(), existingBurn.amount + newDebt.amount);

        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(existingBurn.burnId);
        vm.warp(readyAt);
        reserve.executeWithdrawal(existingBurn);
        reserve.executeWithdrawal(newDebt);
        assertTrue(reserve.paidBurns(existingBurn.burnId));
        assertTrue(reserve.paidBurns(newDebt.burnId));
        assertEq(token.balanceOf(BOB), existingBurn.amount + newDebt.amount);
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

    function testAcceptedDebtExecutesIfVerifierChangesAfterQueue() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        vm.warp(block.timestamp + 1 days);
        burnVerifier.setConfigHash(keccak256("changed after proof admission"));
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(reserve.totalReleased(), b.amount);
        assertEq(reserve.totalPendingAmount(), 0);
    }

    function testEpochBoundPauseCannotInvalidateReviewedReplacementQueue() public {
        uint64 observedEpoch = reserve.queueEpoch();
        (USDOMProofReserve.FinalizedBurn memory oldBurn,) = queued(100e6);
        guardian.execute(
            address(reserve),
            abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (observedEpoch, reserve.pilotAuthorizationGeneration()))
        );
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

        bytes memory stalePause =
            abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (observedEpoch, reserve.pilotAuthorizationGeneration()));
        vm.expectRevert(USDOMProofReserve.StaleEmergency.selector);
        guardian.execute(address(reserve), stalePause);
        assertFalse(reserve.paused());
        assertEq(reserve.pendingCount(), 1);
        assertEq(reserve.totalPendingAmount(), oldBurn.amount);

        uint64 currentEpoch = reserve.queueEpoch();
        uint64 currentPilotGeneration = reserve.pilotAuthorizationGeneration();
        vm.prank(ALICE);
        vm.expectRevert(USDOMProofReserve.Unauthorized.selector);
        reserve.pauseQueueEpoch(currentEpoch, currentPilotGeneration);

        guardian.execute(
            address(reserve), abi.encodeCall(USDOMProofReserve.pauseQueueEpoch, (currentEpoch, currentPilotGeneration))
        );
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
        assertEq(reserve.latestProvedBurnStatements(original.burnId), reserve.burnStatementHash(changed));
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
        assertEq(reserve.latestProvedBurnStatements(original.burnId), reserve.burnStatementHash(original));
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
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(reserve.provedBurnStatements(b.burnId), originallyProvedStatement);
        assertTrue(originalConfig != burnVerifier.verifierConfigHash());
        assertEq(token.balanceOf(BOB), b.amount);
        assertEq(reserve.totalPendingAmount(), 0);
    }

    function testExactLatestStatementCanRequeueWithoutLiveVerifier() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        bytes32 statementHash = reserve.burnStatementHash(b);
        assertEq(reserve.latestProvedBurnStatements(b.burnId), statementHash);

        guardian.execute(address(reserve), abi.encodeCall(USDOMProofReserve.pause, ()));
        reserve.discardWithdrawal(b.burnId);
        govern(abi.encodeCall(USDOMProofReserve.scheduleResume, ()));
        vm.warp(block.timestamp + reserve.governanceDelay());
        reserve.executeResume();

        burnVerifier.setConfigHash(keccak256("permanent verifier outage after admission"));
        reserve.queueWithdrawal(b, bytes(""));
        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(b.burnId);
        vm.warp(readyAt);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertEq(token.balanceOf(BOB), b.amount);
    }

    function testExactLatestStatementCanRequeueAfterFinalitySlotAgesOut() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        bytes32 firstStatement = reserve.provedBurnStatements(b.burnId);
        bytes32 latestStatement = reserve.latestProvedBurnStatements(b.burnId);
        bytes32 debt = reserve.provedBurnDebts(b.burnId);
        uint64 provedSlot = reserve.provedBurnFinalitySlots(b.burnId);
        uint256 aggregateDebt = reserve.totalProvedDebtAmount();
        (,,, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(b.burnId);

        vm.warp(uint256(expiresAt) + reserve.MAX_FINALITY_AGE_SLOTS() * reserve.ETHEREUM_SECONDS_PER_SLOT() + 1);
        reserve.discardWithdrawal(b.burnId);
        burnVerifier.setConfigHash(keccak256("verifier unavailable after permanent proof"));

        reserve.queueWithdrawal(b, bytes(""));
        assertEq(reserve.provedBurnStatements(b.burnId), firstStatement);
        assertEq(reserve.latestProvedBurnStatements(b.burnId), latestStatement);
        assertEq(reserve.provedBurnDebts(b.burnId), debt);
        assertEq(reserve.provedBurnFinalitySlots(b.burnId), provedSlot);
        assertEq(reserve.totalProvedDebtAmount(), aggregateDebt);
        assertEq(reserve.totalPendingAmount(), b.amount);

        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(b.burnId);
        vm.warp(readyAt);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertTrue(reserve.paidRequests(b.requestId));
        assertEq(reserve.totalProvedDebtAmount(), 0);
    }

    function testAgedLatestStatementCannotAuthorizeAlteredRecipientAmountOrFinality() public {
        (USDOMProofReserve.FinalizedBurn memory original,) = queued(100e6);
        (,,, uint64 expiresAt,,,,) = reserve.pendingWithdrawals(original.burnId);
        vm.warp(uint256(expiresAt) + reserve.MAX_FINALITY_AGE_SLOTS() * reserve.ETHEREUM_SECONDS_PER_SLOT() + 1);
        reserve.discardWithdrawal(original.burnId);

        USDOMProofReserve.FinalizedBurn memory altered =
            abi.decode(abi.encode(original), (USDOMProofReserve.FinalizedBurn));
        altered.recipient = ALICE;
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(altered, bytes(""));
        altered = abi.decode(abi.encode(original), (USDOMProofReserve.FinalizedBurn));
        altered.amount += 1;
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(altered, bytes(""));
        altered = abi.decode(abi.encode(original), (USDOMProofReserve.FinalizedBurn));
        altered.finalityBeaconSlot += 1;
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(altered, bytes(""));
        bytes memory alteredProof = proofFor(altered);
        approve(altered, alteredProof);
        vm.expectRevert(USDOMProofReserve.InvalidBurn.selector);
        reserve.queueWithdrawal(altered, alteredProof);

        assertEq(reserve.totalPendingAmount(), 0);
        assertEq(reserve.totalProvedDebtAmount(), original.amount);
        assertEq(reserve.latestProvedBurnStatements(original.burnId), reserve.burnStatementHash(original));
    }

    function testExecutionFailsClosedOnLatestStatementOrPaidFlagStorageDivergence() public {
        (USDOMProofReserve.FinalizedBurn memory b,) = queued(100e6);
        (,, uint64 readyAt,,,,,) = reserve.pendingWithdrawals(b.burnId);
        vm.warp(readyAt);
        uint256 releasedBefore = reserve.totalReleased();
        uint256 debtBefore = reserve.totalProvedDebtAmount();
        uint256 pendingBefore = reserve.totalPendingAmount();

        bytes32 latestSlot = keccak256(abi.encode(b.burnId, uint256(8)));
        bytes32 latest = vm.load(address(reserve), latestSlot);
        vm.store(address(reserve), latestSlot, keccak256("poisoned latest statement"));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(b);
        vm.store(address(reserve), latestSlot, latest);

        bytes32 paidBurnSlot = keccak256(abi.encode(b.burnId, uint256(3)));
        vm.store(address(reserve), paidBurnSlot, bytes32(uint256(1)));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(b);
        vm.store(address(reserve), paidBurnSlot, bytes32(0));

        bytes32 paidRequestSlot = keccak256(abi.encode(b.requestId, uint256(4)));
        vm.store(address(reserve), paidRequestSlot, bytes32(uint256(1)));
        vm.expectRevert(USDOMProofReserve.PendingMismatch.selector);
        reserve.executeWithdrawal(b);
        vm.store(address(reserve), paidRequestSlot, bytes32(0));

        assertEq(reserve.totalReleased(), releasedBefore);
        assertEq(reserve.totalProvedDebtAmount(), debtBefore);
        assertEq(reserve.totalPendingAmount(), pendingBefore);
        reserve.executeWithdrawal(b);
        assertTrue(reserve.paidBurns(b.burnId));
        assertTrue(reserve.paidRequests(b.requestId));
        assertEq(token.balanceOf(BOB), b.amount);
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
